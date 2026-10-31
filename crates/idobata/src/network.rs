use crate::{
    crypto,
    error::{NETWORK, Result},
    scanner::Scanner,
    types::{Config, TrustedRoom},
    util,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    PeerId, StreamProtocol, Swarm, SwarmBuilder, allow_block_list, connection_limits, identity,
    noise,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    tcp, yamux,
};
use std::{collections::BTreeSet, io, time::Duration};
#[derive(Clone, Default)]
pub struct Codec;
async fn read<T: AsyncRead + Unpin>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    io.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0u8; len];
    io.read_exact(&mut bytes).await?;
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}
async fn write<T: AsyncWrite + Unpin>(io: &mut T, data: Vec<u8>, max: usize) -> io::Result<()> {
    if data.is_empty() || data.len() > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    io.write_all(&(data.len() as u32).to_be_bytes()).await?;
    io.write_all(&data).await?;
    io.close().await
}
impl request_response::Codec for Codec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read(io, 16384).await
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read(io, 4096).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        data: Vec<u8>,
    ) -> io::Result<()> {
        write(io, data, 16384).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        data: Vec<u8>,
    ) -> io::Result<()> {
        write(io, data, 4096).await
    }
}
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub messages: request_response::Behaviour<Codec>,
    pub allowed: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    pub limits: connection_limits::Behaviour,
}
pub fn build(key: identity::Keypair, c: &Config) -> Result<Swarm<Behaviour>> {
    let messages = request_response::Behaviour::with_codec(
        Codec,
        [(
            StreamProtocol::new("/idobata/message/1"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(Duration::from_secs(5))
            .with_max_concurrent_streams(8),
    );
    let limits = connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(8))
        .with_max_pending_outgoing(Some(8))
        .with_max_established(Some(8))
        .with_max_established_per_peer(Some(1));
    let behaviour = Behaviour {
        messages,
        allowed: Default::default(),
        limits: connection_limits::Behaviour::new(limits),
    };
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|_| NETWORK)?
        .with_behaviour(|_| behaviour)
        .map_err(|_| NETWORK)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    for addr in &c.listen {
        swarm
            .listen_on(crypto::address(addr, true)?)
            .map_err(|_| NETWORK)?;
    }
    Ok(swarm)
}
pub fn refresh(
    swarm: &mut Swarm<Behaviour>,
    c: &Config,
    previous: &mut BTreeSet<PeerId>,
    own: &str,
) {
    let mut current = BTreeSet::new();
    for room in c.rooms.values() {
        if crypto::validate_room(room, &Scanner::policy_id(), util::now()).is_err()
            || !room
                .certificate
                .signed
                .members
                .iter()
                .any(|m| m.peer_id == own)
        {
            continue;
        }
        for m in &room.certificate.signed.members {
            if m.peer_id == own {
                continue;
            }
            if let Ok(peer) = m.peer_id.parse::<PeerId>() {
                current.insert(peer);
                swarm.behaviour_mut().allowed.allow_peer(peer);
                for a in &m.addresses {
                    if let Ok(addr) = crypto::address(a, false) {
                        swarm.add_peer_address(peer, addr);
                    }
                }
            }
        }
    }
    for peer in previous.difference(&current) {
        swarm.behaviour_mut().allowed.disallow_peer(*peer);
        let _ = swarm.disconnect_peer_id(*peer);
    }
    *previous = current;
}
pub fn room_for<'a>(c: &'a Config, id: &str, own: &str) -> Option<&'a TrustedRoom> {
    c.rooms.values().find(|r| {
        r.certificate.signed.room_id == id
            && r.certificate
                .signed
                .members
                .iter()
                .any(|m| m.peer_id == own)
            && crypto::validate_room(r, &Scanner::policy_id(), util::now()).is_ok()
    })
}
