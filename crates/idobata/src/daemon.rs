use crate::{
    config, crypto, discussion,
    error::{Error, INVALID, Result, SCANNER, STORAGE},
    ipc,
    network::{self, BehaviourEvent},
    scanner::Scanner,
    storage::{self, Storage},
    types::*,
    util,
};
use fs2::FileExt;
use futures::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use libp2p::{
    PeerId, identity,
    request_response::{self, Message, OutboundRequestId},
    swarm::SwarmEvent,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
struct Bucket {
    tokens: f64,
    last: Instant,
}
impl Bucket {
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() / 6.0).min(2.0);
        self.last = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}
struct Context {
    home: PathBuf,
    key: identity::Keypair,
    own: String,
    scanner: Scanner,
    storage: Storage,
    state: State,
    reservations: HashMap<String, (String, u64)>,
    rates: HashMap<String, Bucket>,
    started: Instant,
    outbound_attempts: u64,
    inbound_requests: u64,
    outbound_failures: u64,
    last_transport_error: Option<&'static str>,
}

fn room_authorized(room: &TrustedRoom, own: &str, own_public_key: &str) -> bool {
    crypto::validate_room(room, &Scanner::policy_id(), util::now()).is_ok()
        && room
            .certificate
            .signed
            .members
            .iter()
            .any(|member| member.peer_id == own && member.public_key == own_public_key)
}

impl Context {
    fn charge(&mut self, owner: &str) -> bool {
        self.rates
            .entry(owner.into())
            .or_insert_with(|| Bucket {
                tokens: 2.0,
                last: Instant::now(),
            })
            .take()
    }
    fn commit(&mut self, next: State) -> Result<()> {
        self.storage.save(&next)?;
        self.state = next;
        Ok(())
    }
    fn room(&self, c: &Config, alias: &str) -> Result<TrustedRoom> {
        let room = c.rooms.get(alias).ok_or(INVALID)?;
        crypto::validate_room(room, &Scanner::policy_id(), util::now())?;
        if !room
            .certificate
            .signed
            .members
            .iter()
            .any(|m| m.peer_id == self.own)
        {
            return Err(INVALID);
        }
        Ok(room.clone())
    }
    fn inspect(&self, draft: &Draft, redact: bool) -> Result<Report> {
        crypto::validate_draft(draft)?;
        self.scanner.scan(draft, redact)
    }
    fn public_sources(&self, alias: &str) -> Result<Vec<crate::knowledge_publication::Source>> {
        let config = config::load(&self.home)?;
        let room = self.room(&config, alias)?;
        if !room.certificate.signed.public {
            return Err(INVALID);
        }
        let mut sources = Vec::new();
        let mut groups = BTreeMap::new();
        for item in self.state.inbox.iter().rev() {
            let Some(cert) = &item.certificate else {
                continue;
            };
            if cert.certificate.signed.room_id != room.certificate.signed.room_id
                || !cert.certificate.signed.public
            {
                continue;
            }
            let envelope: Envelope = serde_json::from_slice(&item.wire).map_err(|_| STORAGE)?;
            if !envelope.payload.options.public {
                continue;
            }
            let group = crate::knowledge::resource_group(
                &room,
                &envelope.payload.sender_peer_id,
                &config.knowledge_operator_history,
            );
            let count = groups.entry(group).or_insert(0);
            if *count >= 4 {
                continue;
            }
            *count += 1;
            sources.push(crate::knowledge_publication::Source::Legacy {
                envelope: Box::new(envelope),
                certificate: Box::new(cert.clone()),
                received_at: item.received_at,
            });
            if sources.len() >= 16 {
                break;
            }
        }
        Ok(sources)
    }
    fn blocked(&mut self, report: Report) -> Reply {
        self.state.rejected_count = self.state.rejected_count.saturating_add(1);
        let _ = self.storage.save(&self.state);
        let mut value = serde_json::to_value(&report).unwrap_or(json!({"status":"scan_failed"}));
        if let Some(obj) = value.as_object_mut() {
            obj.remove("redacted");
            obj.insert("enqueued".into(), false.into());
        }
        Reply::new(report.code, value)
    }
    fn handle(&mut self, owner: &str, request: Request, connections: usize) -> Result<Reply> {
        let c = config::load(&self.home)?;
        match request {
            Request::LedgerStatus
            | Request::LedgerBalance { .. }
            | Request::LedgerQuestions { .. }
            | Request::LedgerQuestion { .. }
            | Request::LedgerSubmit { .. }
            | Request::LedgerVote { .. }
            | Request::LedgerTransaction { .. }
            | Request::LedgerBlocks { .. }
            | Request::LedgerCheckpoint
            | Request::KnowledgePublish { .. }
            | Request::KnowledgeSearch { .. }
            | Request::KnowledgeGet { .. }
            | Request::KnowledgeEvaluate { .. }
            | Request::KnowledgePeers { .. }
            | Request::KnowledgePublicSnapshot { .. }
            | Request::KnowledgeStatus { .. } => Err(INVALID),
            Request::Info => Ok(Reply::new(
                0,
                json!({"status":"ready","version":env!("CARGO_PKG_VERSION"),"peer_id":self.own,"policy_id":Scanner::policy_id(),"scanner_wasm_sha256":Scanner::profile()["wasm_sha256"],"scanner_isolation":"wasm-no-host-imports","connected_peers":connections,"outbox_count":self.state.outbox.len(),"pending_count":self.state.outbox.iter().filter(|m|m.delivered.len()<m.recipients.len() && m.held.is_none()).count(),"held_count":self.state.outbox.iter().filter(|m|m.held.is_some()).count(),"delivered_count":self.state.outbox.iter().filter(|m|m.delivered.len()==m.recipients.len()).count(),"inbox_count":self.state.inbox.len(),"blocked_count":self.state.rejected_count,"outbound_attempts":self.outbound_attempts,"inbound_requests":self.inbound_requests,"outbound_failures":self.outbound_failures,"last_transport_error":self.last_transport_error,"uptime_seconds":self.started.elapsed().as_secs(),"rooms":c.rooms.iter().map(|(name,r)|json!({"name":name,"authorized":room_authorized(r,&self.own,&crypto::public(&self.key)),"public":r.certificate.signed.public,"knowledge_automation_required":r.certificate.signed.knowledge_automation_required,"expires_at":r.certificate.signed.expires_at,"epoch":r.certificate.signed.epoch})).collect::<Vec<_>>() }),
            )),
            Request::Begin => {
                self.reservations
                    .retain(|_, (_, expiry)| *expiry > util::now());
                if self.reservations.len() >= 1024 {
                    return Err(INVALID);
                }
                let id = util::random_id();
                self.reservations
                    .insert(id.clone(), (owner.into(), util::now() + 60));
                Ok(Reply::new(
                    0,
                    json!({"request_id":id,"expires_in_seconds":60,"enqueued":false}),
                ))
            }
            Request::Scan { room, draft } => {
                self.room(&c, &room)?;
                let r = self.inspect(&draft, false)?;
                if r.code != 0 {
                    return Ok(self.blocked(r));
                }
                Ok(Reply::new(
                    0,
                    json!({"status":"passed","enqueued":false,"profile":r.profile,"policy_id":Scanner::policy_id(),"findings":[]}),
                ))
            }
            Request::Prepare { room, draft } => {
                self.room(&c, &room)?;
                let mut report = self.inspect(&draft, true)?;
                if ![0, 20].contains(&report.code) {
                    return Ok(self.blocked(report));
                }
                let mut cleaned = report.redacted.take().ok_or(SCANNER)?;
                cleaned.references.retain(|r| !r.starts_with("[REDACTED_"));
                let recheck = self.inspect(&cleaned, false)?;
                if recheck.code != 0 {
                    return Ok(self.blocked(recheck));
                }
                let id = util::random_id();
                let expires_at = util::now() + 300;
                let mut next = self.state.clone();
                storage::prune(&mut next, util::now());
                if next.prepared.len() >= 256 {
                    return Err(STORAGE);
                }
                next.prepared.push(Prepared {
                    id: id.clone(),
                    owner: owner.into(),
                    room,
                    expires_at,
                    policy_id: Scanner::policy_id(),
                    draft: cleaned,
                });
                self.commit(next)?;
                Ok(Reply::new(
                    0,
                    json!({"status":"prepared","enqueued":false,"prepared_id":id,"expires_at":expires_at,"original_status":report.status,"findings":report.findings,"more_findings":report.more_findings}),
                ))
            }
            Request::Preview { prepared } => {
                let p = self
                    .state
                    .prepared
                    .iter()
                    .find(|p| p.id == prepared && p.owner == owner && p.expires_at > util::now())
                    .ok_or(INVALID)?;
                self.room(&c, &p.room)?;
                Ok(Reply::new(
                    0,
                    json!({"status":"prepared","untrusted":true,"prepared_id":p.id,"draft":p.draft,"expires_at":p.expires_at}),
                ))
            }
            Request::Post {
                room,
                draft,
                prepared,
                request_id,
                options,
            } => {
                if !util::valid_id(&request_id) || draft.is_some() == prepared.is_some() {
                    return Err(INVALID);
                }
                let cert = self.room(&c, &room)?;
                let draft = if let Some(d) = draft {
                    d
                } else {
                    let p = self
                        .state
                        .prepared
                        .iter()
                        .find(|p| {
                            Some(&p.id) == prepared.as_ref()
                                && p.owner == owner
                                && p.room == room
                                && p.expires_at > util::now()
                                && p.policy_id == Scanner::policy_id()
                        })
                        .ok_or(INVALID)?;
                    p.draft.clone()
                };
                let r = self.inspect(&draft, false)?;
                if r.code != 0 {
                    return Ok(self.blocked(r));
                }
                if options.public && !cert.certificate.signed.public {
                    return Err(INVALID);
                }
                discussion::validate(
                    &self.state,
                    &cert.certificate.signed.room_id,
                    &self.own,
                    &draft,
                    &options,
                )?;
                if let Some(old) = self
                    .state
                    .outbox
                    .iter()
                    .find(|m| m.request_id == request_id)
                {
                    let env: Envelope = serde_json::from_slice(&old.wire).map_err(|_| STORAGE)?;
                    if old.owner != owner
                        || old.room_alias != room
                        || util::canonical(&env.payload.draft())? != util::canonical(&draft)?
                        || env.payload.options != options
                    {
                        return Err(INVALID);
                    }
                    return self.status(owner, &request_id);
                }
                let reservation = self.reservations.get(&request_id).ok_or(INVALID)?;
                if reservation.0 != owner || reservation.1 <= util::now() {
                    return Err(INVALID);
                }
                if !self.charge(&format!("post:{owner}")) {
                    return Err(Error::new(30, "rate_limited"));
                }
                let recipients = cert
                    .certificate
                    .signed
                    .members
                    .iter()
                    .filter(|m| m.peer_id != self.own)
                    .map(|m| m.peer_id.clone())
                    .collect::<Vec<_>>();
                if recipients.is_empty() {
                    return Err(INVALID);
                }
                let env = crypto::new_envelope_with_options(
                    &self.key,
                    &cert.certificate.signed,
                    &Scanner::policy_id(),
                    draft,
                    options,
                )?;
                let wire = util::canonical(&env)?;
                let mut next = self.state.clone();
                storage::prune(&mut next, util::now());
                if next.outbox.len() >= 4096 {
                    return Err(STORAGE);
                }
                next.outbox.push(Outbox {
                    request_id: request_id.clone(),
                    owner: owner.into(),
                    room_alias: room,
                    created_at: env.payload.created_at,
                    expires_at: env.payload.expires_at,
                    wire,
                    recipients,
                    delivered: BTreeMap::new(),
                    held: None,
                });
                self.commit(next)?;
                self.reservations.remove(&request_id);
                self.status(owner, &request_id)
            }
            Request::Status { request_id } => self.status(owner, &request_id),
            Request::Search {
                room,
                query,
                thread,
                limit,
            } => {
                let r = self.room(&c, &room)?;
                if query.len() > 256
                    || !(1..=100).contains(&limit)
                    || thread.as_ref().is_some_and(|id| !util::valid_id(id))
                {
                    return Err(INVALID);
                }
                let all = discussion::messages(&self.state, &r.certificate.signed.room_id);
                let mut found = all
                    .iter()
                    .rev()
                    .filter(|e| {
                        (query.is_empty()
                            || e.payload.title.contains(&query)
                            || e.payload.body.contains(&query))
                            && thread
                                .as_ref()
                                .is_none_or(|id| discussion::thread_root(&all, e) == id)
                    })
                    .take(limit)
                    .map(|e| discussion::render(&all, e))
                    .collect::<Vec<_>>();
                while serde_json::to_vec(&found).map_err(|_| INVALID)?.len() > 58000 {
                    found.pop();
                }
                Ok(Reply::new(
                    0,
                    json!({"status":"ok","untrusted":true,"messages":found,"retention_days":7}),
                ))
            }
            Request::PublicSnapshot { room, before } => {
                if before.as_ref().is_some_and(|id| !util::valid_id(id)) {
                    return Err(INVALID);
                }
                let r = self.room(&c, &room)?;
                if !r.certificate.signed.public {
                    return Err(INVALID);
                }
                let mut entries = vec![];
                let mut started = before.is_none();
                let mut next_before = None;
                for item in self.state.inbox.iter().rev() {
                    let Some(cert) = &item.certificate else {
                        continue;
                    };
                    let env: Envelope = serde_json::from_slice(&item.wire).map_err(|_| STORAGE)?;
                    if env.payload.room_id != r.certificate.signed.room_id
                        || !env.payload.options.public
                        || !cert.certificate.signed.public
                    {
                        continue;
                    }
                    if !started {
                        if before.as_ref() == Some(&env.payload.message_id) {
                            started = true;
                        }
                        continue;
                    }
                    let peer = env.payload.sender_peer_id.parse().map_err(|_| INVALID)?;
                    crypto::verify_message(
                        &env,
                        &peer,
                        cert,
                        &Scanner::policy_id(),
                        item.received_at,
                    )?;
                    if self.inspect(&env.payload.draft(), false)?.code != 0 {
                        continue;
                    }
                    entries.push(json!({"content":env.payload.draft(),"published_at":env.payload.created_at,
                        "origin":{"message_id":env.payload.message_id,
                            "author":format!("agent-{}",&util::hash(env.payload.sender_peer_id.as_bytes())[..8]),
                            "reply_to":env.payload.options.reply_to,"resolution":env.payload.options.resolution}}));
                    if serde_json::to_vec(&entries).map_err(|_| INVALID)?.len() > 58000 {
                        entries.pop();
                        next_before = entries.last().map(|v| v["origin"]["message_id"].clone());
                        break;
                    }
                    if entries.len() == 20 {
                        next_before = entries.last().map(|v| v["origin"]["message_id"].clone());
                        break;
                    }
                }
                if !started {
                    return Err(INVALID);
                }
                Ok(Reply::new(
                    0,
                    json!({"status":"ok","entries":entries,"next_before":next_before}),
                ))
            }
            Request::Inbox { room, limit } => {
                let r = self.room(&c, &room)?;
                if limit == 0 || limit > 100 {
                    return Err(INVALID);
                }
                let mut messages = vec![];
                for m in self.state.inbox.iter().rev() {
                    let env: Envelope = serde_json::from_slice(&m.wire).map_err(|_| STORAGE)?;
                    if env.payload.room_id != r.certificate.signed.room_id {
                        continue;
                    }
                    let mut rendered = discussion::render(
                        &discussion::messages(&self.state, &r.certificate.signed.room_id),
                        &env,
                    );
                    rendered["local_id"] = m.id.clone().into();
                    rendered["received_at"] = m.received_at.into();
                    messages.push(rendered);
                    if messages.len() >= limit {
                        break;
                    }
                }
                // Keep one IPC reply within the same fixed frame limit as requests.
                while serde_json::to_vec(&messages).map_err(|_| INVALID)?.len() > 60000 {
                    messages.pop();
                }
                Ok(Reply::new(
                    0,
                    json!({"status":"ok","untrusted":true,"messages":messages}),
                ))
            }
        }
    }
    fn status(&self, owner: &str, id: &str) -> Result<Reply> {
        let m = self
            .state
            .outbox
            .iter()
            .find(|m| m.request_id == id && m.owner == owner)
            .ok_or(INVALID)?;
        let delivered = !m.delivered.is_empty();
        Ok(Reply::new(
            if delivered { 0 } else { 10 },
            json!({"status":if m.held.is_some(){"held"}else if delivered{"delivered"}else{"accepted"},"enqueued":true,"request_id":m.request_id,"delivered_count":m.delivered.len(),"recipient_count":m.recipients.len(),"recipients":m.recipients.iter().enumerate().map(|(i,p)|json!({"peer_ref":format!("peer-{}",i+1),"delivered":m.delivered.contains_key(p)})).collect::<Vec<_>>(),"reason":m.held}),
        ))
    }
    fn receive(&mut self, peer: PeerId, wire: Vec<u8>) -> Result<Acknowledgement> {
        self.inbound_requests += 1;
        if wire.len() > crypto::MAX_WIRE {
            return Err(INVALID);
        }
        let env: Envelope = serde_json::from_slice(&wire).map_err(|_| INVALID)?;
        if util::canonical(&env)? != wire {
            return Err(INVALID);
        }
        let c = config::load(&self.home)?;
        let room = network::room_for(&c, &env.payload.room_id, &self.own).ok_or(INVALID)?;
        crypto::verify_message(&env, &peer, room, &Scanner::policy_id(), util::now())?;
        let digest = util::hash(&util::canonical(&env.payload)?);
        if let Some(old) = self.state.inbox.iter().find(|m| {
            m.ack.receipt.message_id == env.payload.message_id
                && serde_json::from_slice::<Envelope>(&m.wire)
                    .map(|e| e.payload.sender_peer_id == env.payload.sender_peer_id)
                    .unwrap_or(false)
        }) {
            if old.ack.receipt.payload_digest != digest {
                return Err(INVALID);
            }
            return Ok(old.ack.clone());
        }
        if !self.charge(&format!("receive:{peer}")) {
            return Err(Error::new(30, "rate_limited"));
        }
        if discussion::messages(&self.state, &env.payload.room_id)
            .iter()
            .any(|old| {
                old.payload.message_id == env.payload.message_id
                    && old.payload.sender_peer_id != env.payload.sender_peer_id
            })
        {
            return Err(INVALID);
        }
        let report = self.inspect(&env.payload.draft(), false)?;
        if report.code != 0 {
            self.state.rejected_count += 1;
            let _ = self.storage.save(&self.state);
            return Err(Error::new(report.code, "content_rejected"));
        }
        discussion::validate(
            &self.state,
            &env.payload.room_id,
            &env.payload.sender_peer_id,
            &env.payload.draft(),
            &env.payload.options,
        )?;
        let accepted_at = util::now();
        crypto::verify_message(&env, &peer, room, &Scanner::policy_id(), accepted_at)?;
        let receipt = Receipt {
            version: 1,
            room_id: env.payload.room_id.clone(),
            message_id: env.payload.message_id.clone(),
            payload_digest: digest,
            receiver_peer_id: self.own.clone(),
            received_at: accepted_at,
        };
        let ack = Acknowledgement {
            signature: crypto::sign(&self.key, "idobata.receipt.v1", &receipt)?,
            receipt,
        };
        let mut next = self.state.clone();
        storage::prune(&mut next, util::now());
        if next.inbox.len() >= 4096 {
            return Err(STORAGE);
        }
        next.inbox.push(Inbox {
            id: util::random_id(),
            wire,
            ack: ack.clone(),
            received_at: accepted_at,
            certificate: Some(room.clone()),
        });
        self.commit(next)?;
        Ok(ack)
    }
    fn acknowledge(&mut self, id: &str, peer: PeerId, ack: Acknowledgement) -> Result<()> {
        let c = config::load(&self.home)?;
        let old = self
            .state
            .outbox
            .iter()
            .find(|m| m.request_id == id)
            .ok_or(INVALID)?;
        let env: Envelope = serde_json::from_slice(&old.wire).map_err(|_| STORAGE)?;
        let room = self.room(&c, &old.room_alias)?;
        crypto::verify_message(
            &env,
            &self.own.parse().map_err(|_| INVALID)?,
            &room,
            &Scanner::policy_id(),
            util::now(),
        )?;
        let member = room
            .certificate
            .signed
            .members
            .iter()
            .find(|m| m.peer_id == peer.to_string())
            .ok_or(INVALID)?;
        let r = &ack.receipt;
        if r.version != 1
            || r.receiver_peer_id != peer.to_string()
            || r.room_id != env.payload.room_id
            || r.message_id != env.payload.message_id
            || r.payload_digest != util::hash(&util::canonical(&env.payload)?)
            || r.received_at > util::now() + 300
            || r.received_at + 300 < env.payload.created_at
        {
            return Err(INVALID);
        }
        crypto::verify(
            &crypto::public_key(&member.public_key)?,
            "idobata.receipt.v1",
            r,
            &ack.signature,
        )?;
        let mut next = self.state.clone();
        let m = next
            .outbox
            .iter_mut()
            .find(|m| m.request_id == id)
            .ok_or(INVALID)?;
        if !m.recipients.contains(&peer.to_string()) {
            return Err(INVALID);
        }
        m.delivered.insert(peer.to_string(), ack);
        self.commit(next)
    }
    fn deliverable(&self, m: &Outbox, c: &Config) -> bool {
        let Ok(room) = self.room(c, &m.room_alias) else {
            return false;
        };
        let Ok(env) = serde_json::from_slice::<Envelope>(&m.wire) else {
            return false;
        };
        if crypto::verify_message(
            &env,
            &self.own.parse().expect("validated identity"),
            &room,
            &Scanner::policy_id(),
            util::now(),
        )
        .is_err()
        {
            return false;
        }
        self.inspect(&env.payload.draft(), false)
            .map(|r| r.code == 0)
            .unwrap_or(false)
    }
}
struct Delivery {
    allowed: BTreeSet<PeerId>,
    pending: HashMap<OutboundRequestId, (String, PeerId)>,
    retry: HashMap<(String, PeerId), (Instant, u32)>,
    last_prune: Instant,
}
fn transport_event(
    ctx: &mut Context,
    swarm: &mut libp2p::Swarm<network::Behaviour>,
    delivery: &mut Delivery,
    event: SwarmEvent<BehaviourEvent>,
) -> Result<()> {
    match event {
        SwarmEvent::Behaviour(BehaviourEvent::Messages(request_response::Event::Message {
            peer,
            message,
            ..
        })) => match message {
            Message::Request {
                request, channel, ..
            } => {
                let response = match ctx.receive(peer, request) {
                    Ok(ack) => WireResponse::Accepted { ack },
                    Err(e) => WireResponse::Rejected { code: e.code },
                };
                if let Ok(bytes) = util::canonical(&response) {
                    let _ = swarm.behaviour_mut().messages.send_response(channel, bytes);
                }
            }
            Message::Response {
                request_id,
                response,
            } => {
                if let Some((id, expected)) = delivery.pending.remove(&request_id)
                    && peer == expected
                    && let Ok(WireResponse::Accepted { ack }) = serde_json::from_slice(&response)
                {
                    let _ = ctx.acknowledge(&id, peer, ack);
                }
            }
        },
        SwarmEvent::Behaviour(BehaviourEvent::Messages(
            request_response::Event::OutboundFailure {
                request_id, error, ..
            },
        )) => {
            delivery.pending.remove(&request_id);
            ctx.outbound_failures += 1;
            ctx.last_transport_error = Some(match error {
                request_response::OutboundFailure::Timeout => "timeout",
                request_response::OutboundFailure::DialFailure => "dial_failed",
                request_response::OutboundFailure::ConnectionClosed => "connection_closed",
                request_response::OutboundFailure::UnsupportedProtocols => "protocol_unavailable",
                request_response::OutboundFailure::Io(_) => "io_failed",
            });
        }
        SwarmEvent::ListenerError { .. } => return Err(crate::error::NETWORK),
        _ => {}
    }
    Ok(())
}
fn poll_delivery(
    ctx: &mut Context,
    swarm: &mut libp2p::Swarm<network::Behaviour>,
    delivery: &mut Delivery,
) -> Result<()> {
    let Ok(current) = config::load(&ctx.home) else {
        for peer in std::mem::take(&mut delivery.allowed) {
            swarm.behaviour_mut().allowed.disallow_peer(peer);
            let _ = swarm.disconnect_peer_id(peer);
        }
        return Ok(());
    };
    network::refresh(swarm, &current, &mut delivery.allowed, &ctx.own);
    ctx.reservations
        .retain(|_, (_, expiry)| *expiry > util::now());
    if delivery.last_prune.elapsed() >= Duration::from_secs(60) {
        let mut next = ctx.state.clone();
        storage::prune(&mut next, util::now());
        ctx.commit(next)?;
        let ids: BTreeSet<_> = ctx
            .state
            .outbox
            .iter()
            .map(|m| m.request_id.clone())
            .collect();
        delivery.retry.retain(|(id, _), _| ids.contains(id));
        delivery.last_prune = Instant::now();
    }
    // Clone only the work that can run in this bounded batch, not the whole retained store.
    let queued: Vec<_> = ctx
        .state
        .outbox
        .iter()
        .filter(|message| {
            message.delivered.len() != message.recipients.len()
                && message.recipients.iter().any(|recipient| {
                    let Ok(peer) = recipient.parse::<PeerId>() else {
                        return false;
                    };
                    !message.delivered.contains_key(recipient)
                        && !delivery
                            .pending
                            .values()
                            .any(|(id, p)| id == &message.request_id && p == &peer)
                        && delivery
                            .retry
                            .get(&(message.request_id.clone(), peer))
                            .is_none_or(|(due, _)| *due <= Instant::now())
                })
        })
        .take(8)
        .cloned()
        .collect();
    for message in queued {
        if delivery.pending.len() >= 8 {
            break;
        }
        if !ctx.deliverable(&message, &current) {
            if message.held.is_none() {
                let mut next = ctx.state.clone();
                if let Some(m) = next
                    .outbox
                    .iter_mut()
                    .find(|m| m.request_id == message.request_id)
                {
                    m.held = Some("authorization_policy_or_expiry".into());
                }
                ctx.commit(next)?;
            }
            for r in &message.recipients {
                if let Ok(p) = r.parse() {
                    delivery.retry.insert(
                        (message.request_id.clone(), p),
                        (Instant::now() + Duration::from_secs(30), 0),
                    );
                }
            }
            continue;
        }
        if message.held.is_some() {
            let mut next = ctx.state.clone();
            if let Some(m) = next
                .outbox
                .iter_mut()
                .find(|m| m.request_id == message.request_id)
            {
                m.held = None;
            }
            ctx.commit(next)?;
        }
        for recipient in &message.recipients {
            if delivery.pending.len() >= 8 {
                break;
            }
            if message.delivered.contains_key(recipient) {
                continue;
            }
            let peer: PeerId = recipient.parse().map_err(|_| INVALID)?;
            if delivery
                .pending
                .values()
                .any(|(id, p)| id == &message.request_id && p == &peer)
            {
                continue;
            }
            let route = (message.request_id.clone(), peer);
            let (due, attempt) = delivery
                .retry
                .get(&route)
                .copied()
                .unwrap_or((Instant::now(), 0));
            if due > Instant::now() || !delivery.allowed.contains(&peer) {
                continue;
            }
            let outbound = swarm
                .behaviour_mut()
                .messages
                .send_request(&peer, message.wire.clone());
            delivery
                .pending
                .insert(outbound, (message.request_id.clone(), peer));
            ctx.outbound_attempts += 1;
            let delay = 2u64.saturating_pow(attempt.min(4) + 1).min(30);
            delivery.retry.insert(
                route,
                (Instant::now() + Duration::from_secs(delay), attempt + 1),
            );
        }
    }
    Ok(())
}
// Agent requests remain on the same authenticated IPC connection while the
// existing bounded knowledge queries fetch proofs. Never await here: doing so
// would stop the swarm that must deliver those query responses.
enum LedgerIntent {
    Submit(crate::ledger::Operation),
    Vote {
        question: String,
        answer: String,
        verdict: crate::ledger::Verdict,
    },
}
struct PendingLedger {
    intent: LedgerIntent,
    response: tokio::sync::oneshot::Sender<Reply>,
    remaining: usize,
    deadline: Instant,
}
#[derive(Default)]
struct LedgerBroker {
    next: u64,
    pending: BTreeMap<u64, PendingLedger>,
    replies: FuturesUnordered<BoxFuture<'static, (u64, Reply)>>,
}
fn ledger_reply(result: Result<serde_json::Value>) -> Reply {
    match result {
        Ok(value) => {
            let code = match value["status"].as_str() {
                Some(
                    "pending" | "hold" | "unknown" | "pruned" | "expired_or_replaced" | "not_found",
                ) => 10,
                Some("fault") => 30,
                _ => 0,
            };
            Reply::new(code, value)
        }
        Err(e) => Reply::new(
            e.code,
            json!({"status":if e.code==10 {"hold"}else{"failed"},"error":e.error,"finalized":false,"experiment_only":true}),
        ),
    }
}
fn ledger_handles(request: &Request) -> bool {
    matches!(
        request,
        Request::LedgerStatus
            | Request::LedgerBalance { .. }
            | Request::LedgerQuestions { .. }
            | Request::LedgerQuestion { .. }
            | Request::LedgerSubmit { .. }
            | Request::LedgerVote { .. }
            | Request::LedgerTransaction { .. }
            | Request::LedgerBlocks { .. }
            | Request::LedgerCheckpoint
    )
}
fn ledger_mutation_reply(result: Result<serde_json::Value>) -> Reply {
    match result {
        Err(error) if error.code == STORAGE.code && error.error == STORAGE.error => Reply::new(
            error.code,
            json!({"status":"unknown","error":error.error,"enqueued":null,"finalized":null,"retry_policy":"inspect_ledger_status_recent_submissions_and_wallet_nonce_before_resubmitting","experiment_only":true}),
        ),
        result => ledger_reply(result),
    }
}
fn apply_ledger_intent(
    intent: LedgerIntent,
    ledger: &mut crate::ledger_runtime::Runtime,
    knowledge: &crate::knowledge_runtime::Runtime,
) -> Reply {
    ledger_mutation_reply(match intent {
        LedgerIntent::Submit(operation) => ledger.submit_from_knowledge(operation, knowledge),
        LedgerIntent::Vote {
            question,
            answer,
            verdict,
        } => ledger.cast_vote_from_knowledge(&question, &answer, verdict, knowledge),
    })
}
impl LedgerBroker {
    fn command(
        &mut self,
        command: ipc::Command,
        ledger: &mut crate::ledger_runtime::Runtime,
        knowledge: &mut crate::knowledge_runtime::Runtime,
        swarm: &mut libp2p::Swarm<network::Behaviour>,
    ) {
        let ipc::Command {
            owner,
            request,
            response,
        } = command;
        let intent = match request {
            Request::LedgerSubmit { operation } => LedgerIntent::Submit(operation),
            Request::LedgerVote {
                question,
                answer,
                verdict,
            } => LedgerIntent::Vote {
                question,
                answer,
                verdict,
            },
            request => {
                let result = match request {
                    Request::LedgerStatus => Ok(ledger.status()),
                    Request::LedgerBalance { peer_id } => ledger.balance(peer_id.as_deref()),
                    Request::LedgerQuestions { limit, cursor } => {
                        ledger.questions(limit, cursor.as_deref())
                    }
                    Request::LedgerQuestion { id } => ledger.question(&id),
                    Request::LedgerTransaction { id } => ledger.transaction(&id),
                    Request::LedgerBlocks { from, limit } => ledger.blocks(from, limit),
                    Request::LedgerCheckpoint => ledger.checkpoint(),
                    _ => Err(INVALID),
                };
                let _ = response.send(ledger_reply(result));
                return;
            }
        };
        let required = match &intent {
            LedgerIntent::Submit(operation) => ledger.required_records(operation),
            LedgerIntent::Vote {
                question, answer, ..
            } => ledger.required_vote_records(question, answer),
        };
        let ids = match required {
            Ok(ids) if ids.len() <= 3 => ids,
            Ok(_) => {
                let _ = response.send(ledger_reply(Err(INVALID)));
                return;
            }
            Err(e) => {
                let _ = response.send(ledger_reply(Err(e)));
                return;
            }
        };
        if ids.is_empty() {
            let _ = response.send(apply_ledger_intent(intent, ledger, knowledge));
            return;
        }
        if self.pending.len() >= 8 || self.replies.len().saturating_add(ids.len()) > 24 {
            let _ = response.send(ledger_reply(Err(Error::new(
                10,
                "ledger_reference_queue_full",
            ))));
            return;
        }
        let Some(room) = ledger.room_alias().map(str::to_owned) else {
            let _ = response.send(ledger_reply(Err(Error::new(10, "ledger_not_configured"))));
            return;
        };
        let Some(id) = self.next.checked_add(1) else {
            let _ = response.send(ledger_reply(Err(STORAGE)));
            return;
        };
        self.next = id;
        self.pending.insert(
            id,
            PendingLedger {
                intent,
                response,
                remaining: ids.len(),
                deadline: Instant::now() + Duration::from_secs(8),
            },
        );
        for record in ids {
            let (response, rx) = tokio::sync::oneshot::channel();
            knowledge.command(
                ipc::Command {
                    owner: owner.clone(),
                    request: Request::KnowledgeGet {
                        room: room.clone(),
                        id: record,
                    },
                    response,
                },
                swarm,
            );
            self.replies.push(
                async move {
                    (
                        id,
                        rx.await
                            .unwrap_or_else(|_| Reply::new(40, json!({"status":"failed"}))),
                    )
                }
                .boxed(),
            );
        }
    }
    fn completed(
        &mut self,
        id: u64,
        reply: Reply,
        ledger: &mut crate::ledger_runtime::Runtime,
        knowledge: &crate::knowledge_runtime::Runtime,
    ) {
        let Some(job) = self.pending.get_mut(&id) else {
            return;
        };
        if reply.code != 0 || job.deadline <= Instant::now() || job.response.is_closed() {
            if let Some(job) = self.pending.remove(&id) {
                let _ = job.response.send(ledger_reply(Err(Error::new(
                    10,
                    "ledger_reference_unavailable",
                ))));
            }
            return;
        }
        job.remaining -= 1;
        if job.remaining == 0 {
            let job = self
                .pending
                .remove(&id)
                .expect("pending job was just found");
            let _ = job
                .response
                .send(apply_ledger_intent(job.intent, ledger, knowledge));
        }
    }
    fn expire(&mut self) {
        let expired = self
            .pending
            .iter()
            .filter(|(_, job)| job.deadline <= Instant::now() || job.response.is_closed())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(job) = self.pending.remove(&id) {
                let _ = job.response.send(ledger_reply(Err(Error::new(
                    10,
                    "ledger_reference_deadline",
                ))));
            }
        }
    }
}

pub async fn run(home: &Path) -> Result<()> {
    util::disable_core_dumps();
    let c = config::load(home)?;
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let lock = opts.open(home.join("daemon.lock")).map_err(|_| STORAGE)?;
    lock.try_lock_exclusive()
        .map_err(|_| Error::new(30, "daemon_already_running"))?;
    let key = crypto::load_key(home)?;
    let own = key.public().to_peer_id().to_string();
    let scanner = Scanner::new()?;
    let storage = Storage::open(home)?;
    let mut state = storage.load()?;
    storage::prune(&mut state, util::now());
    let mut swarm = network::build(key.clone(), &c).await?;
    let mut delivery = Delivery {
        allowed: BTreeSet::new(),
        pending: HashMap::new(),
        retry: HashMap::new(),
        last_prune: Instant::now(),
    };
    network::refresh(&mut swarm, &c, &mut delivery.allowed, &own);
    let mut knowledge = crate::knowledge_runtime::Runtime::open(home, key.clone())?;
    let mut ledger = crate::ledger_runtime::Runtime::open(home, key.clone())?;
    let mut ledger_broker = LedgerBroker::default();
    let mut ctx = Context {
        home: home.into(),
        key,
        own,
        scanner,
        storage,
        state,
        reservations: HashMap::new(),
        rates: HashMap::new(),
        started: Instant::now(),
        outbound_attempts: 0,
        inbound_requests: 0,
        outbound_failures: 0,
        last_transport_error: None,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let mut ipc_task = tokio::spawn(ipc::serve(c, tx));
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    // Keep the signal receiver alive while processing a frame; do not lose SIGINT.
    let shutdown = async {
        #[cfg(unix)]
        {
            if let Ok(mut signal) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _=signal.recv()=>{}, _=tokio::signal::ctrl_c()=>{} }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    tokio::pin!(shutdown);
    println!(
        "{}",
        json!({"event":"daemon_started","peer_id":ctx.own,"policy_id":Scanner::policy_id()})
    );
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            result=&mut ipc_task=>{return result.map_err(|_|STORAGE)?},
            Some(command)=rx.recv()=>{
                if ledger_handles(&command.request) {
                    ledger_broker.command(command,&mut ledger,&mut knowledge,&mut swarm);
                } else if let Request::KnowledgePublicSnapshot {room,cursor,forget_only,..}=&command.request {
                    let legacy=if cursor.is_none() && !forget_only {ctx.public_sources(room)}else{Ok(vec![])};
                    match legacy {
                        Ok(legacy)=>knowledge.public_command(command,legacy,&mut swarm),
                        Err(e)=>{let _=command.response.send(Reply::new(e.code,json!({"status":"failed","error":e.error})));}
                    }
                } else if crate::knowledge_runtime::Runtime::handles(&command.request) {
                    knowledge.command(command,&mut swarm);
                } else {
                    let info=matches!(&command.request,Request::Info);
                    let reply=ctx.handle(&command.owner,command.request,swarm.connected_peers().count());
                    let mut reply=reply.unwrap_or_else(|e|Reply::new(e.code,json!({"status":"failed","error":e.error,"enqueued":false})));
                    if info {reply.result["knowledge"]=knowledge.metrics();reply.result["ledger"]=ledger.status();}
                    let _=command.response.send(reply);
                }
            },
            event=swarm.select_next_some()=>match event {
                SwarmEvent::Behaviour(BehaviourEvent::Knowledge(event))=>knowledge.event(event,&mut swarm),
                SwarmEvent::Behaviour(BehaviourEvent::Ledger(event))=>ledger.event(event,&mut swarm),
                event=>transport_event(&mut ctx,&mut swarm,&mut delivery,event)?,
            },
            Some((id,reply))=ledger_broker.replies.next(), if !ledger_broker.replies.is_empty()=>ledger_broker.completed(id,reply,&mut ledger,&knowledge),
            _=interval.tick()=>{poll_delivery(&mut ctx,&mut swarm,&mut delivery)?;knowledge.poll(&mut swarm);ledger.poll(&mut swarm,&knowledge);ledger_broker.expire();},
        }
    }
    ipc_task.abort();
    ctx.storage.save(&ctx.state)?;
    drop(lock);
    Ok(())
}

#[cfg(test)]
mod authorization_display_tests {
    use super::*;

    #[test]
    fn valid_certificate_without_own_key_is_not_reported_as_authorized() {
        let issuer = identity::Keypair::generate_ed25519();
        let other = identity::Keypair::generate_ed25519();
        let own = issuer.public().to_peer_id().to_string();
        let now = util::now();
        let signed = Room {
            version: 1,
            room_id: util::random_id(),
            epoch: 1,
            issued_at: now,
            expires_at: now + 3600,
            policy_id: Scanner::policy_id(),
            members: [&issuer, &other]
                .into_iter()
                .map(|key| Member {
                    peer_id: key.public().to_peer_id().to_string(),
                    public_key: crypto::public(key),
                    addresses: vec![],
                })
                .collect(),
            public: false,
            knowledge_automation_required: false,
            knowledge_operators: None,
        };
        let mut room = TrustedRoom {
            authority_peer_id: own.clone(),
            certificate: Signed {
                signature: crypto::sign(&issuer, "idobata.room.v1", &signed).unwrap(),
                public_key: crypto::public(&issuer),
                signed,
            },
        };
        assert!(room_authorized(&room, &own, &crypto::public(&issuer)));
        assert!(!room_authorized(&room, &own, &crypto::public(&other)));
        room.certificate
            .signed
            .members
            .retain(|member| member.peer_id != own);
        room.certificate.signed.epoch += 1;
        room.certificate.signature =
            crypto::sign(&issuer, "idobata.room.v1", &room.certificate.signed).unwrap();
        crypto::validate_room(&room, &Scanner::policy_id(), now).unwrap();
        assert!(!room_authorized(&room, &own, &crypto::public(&issuer)));
        assert!(room_authorized(
            &room,
            &other.public().to_peer_id().to_string(),
            &crypto::public(&other)
        ));
    }
}

#[cfg(test)]
mod ledger_ipc_tests {
    use super::*;

    #[test]
    fn pending_and_unknown_ledger_results_are_not_reported_as_final_success() {
        for status in [
            "hold",
            "pending",
            "unknown",
            "pruned",
            "expired_or_replaced",
            "not_found",
        ] {
            assert_eq!(ledger_reply(Ok(json!({"status":status}))).code, 10);
        }
        assert_eq!(ledger_reply(Ok(json!({"status":"confirmed"}))).code, 0);
        assert_eq!(ledger_reply(Ok(json!({"status":"fault"}))).code, 30);
        let denied = ledger_reply(Err(Error::new(10, "ledger_reference_unavailable")));
        assert_eq!(denied.result["finalized"], false);
    }

    #[test]
    fn storage_error_after_mutation_does_not_claim_transaction_absence() {
        // atomic rename may have succeeded before parent-directory fsync failed;
        // the protected pending transaction can reappear during recovery.
        let reply = ledger_mutation_reply(Err(STORAGE));
        assert_eq!(reply.code, 22);
        assert_eq!(reply.result["status"], "unknown");
        assert!(reply.result["enqueued"].is_null());
        assert!(reply.result["finalized"].is_null());
        assert!(
            reply.result["retry_policy"]
                .as_str()
                .unwrap()
                .contains("recent_submissions")
        );
        assert_eq!(
            ledger_mutation_reply(Err(INVALID)).result["status"],
            "failed"
        );
        assert_eq!(
            ledger_mutation_reply(Err(SCANNER)).result["status"],
            "failed"
        );
        assert_eq!(
            ledger_mutation_reply(Err(Error::new(22, "knowledge_content_rejected"))).result["status"],
            "failed"
        );
    }

    #[test]
    fn expired_reference_job_cannot_submit_and_late_completion_is_ignored() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("node");
        config::init(&home, vec!["/ip4/127.0.0.1/tcp/34000".into()]).unwrap();
        let key = crypto::load_key(&home).unwrap();
        let mut ledger = crate::ledger_runtime::Runtime::open(&home, key.clone()).unwrap();
        let knowledge = crate::knowledge_runtime::Runtime::open(&home, key).unwrap();
        let (response, mut receiver) = tokio::sync::oneshot::channel();
        let mut broker = LedgerBroker::default();
        broker.pending.insert(
            1,
            PendingLedger {
                intent: LedgerIntent::Submit(crate::ledger::Operation::Transfer {
                    to_peer_id: "unused".into(),
                    amount: 1,
                }),
                response,
                remaining: 1,
                deadline: Instant::now() - Duration::from_secs(1),
            },
        );
        broker.expire();
        assert!(broker.pending.is_empty());
        assert_eq!(
            receiver.try_recv().unwrap().result["error"],
            "ledger_reference_deadline"
        );
        broker.completed(
            1,
            Reply::new(0, json!({"status":"found"})),
            &mut ledger,
            &knowledge,
        );
        assert_eq!(ledger.status()["reason"], "ledger_not_configured");
        assert!(!home.join("ledger-runtime.enc").exists());
    }

    #[test]
    fn corrupt_ledger_configuration_is_a_visible_isolated_fault() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("node");
        config::init(&home, vec!["/ip4/127.0.0.1/tcp/34000".into()]).unwrap();
        util::atomic_write(&home.join("ledger-settings.json"), b"not-json").unwrap();
        let key = crypto::load_key(&home).unwrap();
        let ledger = crate::ledger_runtime::Runtime::open(&home, key.clone()).unwrap();
        assert_eq!(ledger.status()["status"], "fault");
        assert!(crate::knowledge_runtime::Runtime::open(&home, key).is_ok());
        assert_eq!(
            std::fs::read(home.join("ledger-settings.json")).unwrap(),
            b"not-json"
        );
    }
}
