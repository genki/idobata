use crate::{
    crypto,
    error::{INVALID, Result, STORAGE},
    scanner::Scanner,
    types::*,
    util,
};
use libp2p::identity;
use rand::RngCore;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    path::Path,
};
const CONFIG_BYTES: usize = 131072;
const HISTORY_ROOMS: usize = 32;
const HISTORY_PEERS: usize = 256;

fn mutation_lock(home: &Path) -> Result<File> {
    util::protected(home)?;
    let path = home.join("config.lock");
    if path.try_exists().map_err(|_| STORAGE)? {
        util::protected(&path)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(&path).map_err(|_| STORAGE)?;
    if !file.metadata().map_err(|_| STORAGE)?.is_file() {
        return Err(STORAGE);
    }
    util::protected(&path)?;
    fs2::FileExt::lock_exclusive(&file).map_err(|_| STORAGE)?;
    Ok(file)
}

fn validate_operator_history(c: &Config) -> Result<()> {
    if c.knowledge_operator_history.len() > HISTORY_ROOMS {
        return Err(INVALID);
    }
    let mut known = BTreeMap::new();
    for (room_id, history) in &c.knowledge_operator_history {
        if !util::valid_id(room_id)
            || history.authority_peer_id.parse::<libp2p::PeerId>().is_err()
            || history.epoch == 0
            || history.epoch > 9_007_199_254_740_991
            || !util::valid_id(&history.certificate_digest)
            || !history.required
            || history.bindings.len() > HISTORY_PEERS
            || history.bindings.iter().any(|(peer, group)| {
                peer.parse::<libp2p::PeerId>().is_err()
                    || group.is_empty()
                    || group.len() > 128
                    || !group
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            })
        {
            return Err(INVALID);
        }
        for (peer, group) in &history.bindings {
            if known
                .insert((&history.authority_peer_id, peer), group)
                .is_some_and(|previous| previous != group)
            {
                return Err(INVALID);
            }
        }
    }
    Ok(())
}

fn remember_operator_bindings(c: &mut Config, trusted: &TrustedRoom) -> Result<()> {
    let room = &trusted.certificate.signed;
    let old = c.knowledge_operator_history.get(&room.room_id);
    let digest = util::hash(&util::canonical(&trusted.certificate)?);
    if let Some(history) = old
        && (history.authority_peer_id != trusted.authority_peer_id
            || history.public != room.public
            || (history.automation_required && !room.knowledge_automation_required)
            || room.epoch < history.epoch
            || (room.epoch == history.epoch && digest != history.certificate_digest)
            || room.knowledge_operators.is_none())
    {
        return Err(INVALID);
    }
    let Some(claims) = &room.knowledge_operators else {
        return Ok(());
    };
    // Resource budgets share the authority/operator namespace across rooms.
    // A known key must therefore retain the same binding in a new room too.
    for history in c
        .knowledge_operator_history
        .values()
        .filter(|history| history.authority_peer_id == trusted.authority_peer_id)
    {
        for member in &room.members {
            if let Some(known) = history.bindings.get(&member.peer_id)
                && claims.bindings.get(&member.peer_id) != Some(known)
            {
                return Err(INVALID);
            }
        }
    }
    let mut bindings = old
        .map(|history| history.bindings.clone())
        .unwrap_or_default();
    for member in &room.members {
        if let Some(known) = bindings.get(&member.peer_id)
            && claims.bindings.get(&member.peer_id) != Some(known)
        {
            return Err(INVALID);
        }
    }
    for (peer, group) in &claims.bindings {
        if bindings.get(peer).is_some_and(|known| known != group) {
            return Err(INVALID);
        }
        bindings.insert(peer.clone(), group.clone());
    }
    if bindings.len() > HISTORY_PEERS
        || (old.is_none() && c.knowledge_operator_history.len() >= HISTORY_ROOMS)
    {
        return Err(INVALID);
    }
    c.knowledge_operator_history.insert(
        room.room_id.clone(),
        OperatorBindingHistory {
            authority_peer_id: trusted.authority_peer_id.clone(),
            epoch: room.epoch,
            certificate_digest: digest,
            public: room.public,
            automation_required: room.knowledge_automation_required,
            required: true,
            bindings,
        },
    );
    Ok(())
}
pub fn load(home: &Path) -> Result<Config> {
    util::protected(home)?;
    let p = home.join("config.json");
    util::protected(&p)?;
    let c: Config = serde_json::from_slice(&util::read_bounded(&p, CONFIG_BYTES as u64)?)
        .map_err(|_| INVALID)?;
    if c.version != 1
        || c.listen.is_empty()
        || c.listen.len() > 4
        || c.rooms.len() > 32
        || c.endpoint.is_empty()
        || c.endpoint.len() > 512
        || c.client_uids.len() > 32
    {
        return Err(INVALID);
    }
    for a in &c.listen {
        crypto::address(a, true)?;
    }
    for name in c.rooms.keys() {
        if !util::valid_alias(name) {
            return Err(INVALID);
        }
    }
    validate_operator_history(&c)?;
    Ok(c)
}
pub fn save(home: &Path, c: &Config) -> Result<()> {
    // 低水準の永続化。既存設定のread/modify/saveは同じconfig.lock guard内で行う。
    // 外部のOS管理者による直接編集まで、この関数で直列化するものではない。
    validate_operator_history(c)?;
    let bytes = util::canonical(c)?;
    if bytes.len() > CONFIG_BYTES {
        return Err(INVALID);
    }
    util::atomic_write(&home.join("config.json"), &bytes)
}
pub fn init(home: &Path, listen: Vec<String>) -> Result<Member> {
    for a in &listen {
        crypto::address(a, true)?;
    }
    util::private_dir(home)?;
    let _mutation = mutation_lock(home)?;
    if home.join("config.json").exists()
        || home.join("identity.key").exists()
        || home.join("storage.key").exists()
    {
        return Err(INVALID);
    }
    let key = identity::Keypair::generate_ed25519();
    util::atomic_write(
        &home.join("identity.key"),
        &key.to_protobuf_encoding().map_err(|_| STORAGE)?,
    )?;
    let mut storage_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut storage_key);
    util::atomic_write(&home.join("storage.key"), &storage_key)?;
    zeroize::Zeroize::zeroize(&mut storage_key);
    #[cfg(unix)]
    let endpoint = home
        .canonicalize()
        .map_err(|_| STORAGE)?
        .join("ipc.sock")
        .to_str()
        .ok_or(INVALID)?
        .to_owned();
    #[cfg(windows)]
    let endpoint = format!("\\\\.\\pipe\\idobata-{}", &util::random_id()[..24]);
    let config = Config {
        version: 1,
        endpoint,
        listen: listen.clone(),
        rooms: BTreeMap::new(),
        knowledge_operator_history: BTreeMap::new(),
        client_uids: vec![],
        socket_group: None,
        client_sid: None,
    };
    save(home, &config)?;
    Ok(Member {
        peer_id: key.public().to_peer_id().to_string(),
        public_key: crypto::public(&key),
        addresses: listen,
    })
}
pub fn identity(home: &Path, addresses: Vec<String>) -> Result<Member> {
    let c = load(home)?;
    let key = crypto::load_key(home)?;
    let addresses = if addresses.is_empty() {
        c.listen
    } else {
        addresses
    };
    let m = Member {
        peer_id: key.public().to_peer_id().to_string(),
        public_key: crypto::public(&key),
        addresses,
    };
    crypto::member_valid(&m)?;
    Ok(m)
}
pub fn create_room(
    home: &Path,
    alias: &str,
    members: Vec<Member>,
    hours: u64,
) -> Result<Signed<Room>> {
    create_room_with_visibility(home, alias, members, hours, false)
}
pub fn create_room_with_visibility(
    home: &Path,
    alias: &str,
    members: Vec<Member>,
    hours: u64,
    public: bool,
) -> Result<Signed<Room>> {
    create_room_with_policy(home, alias, members, hours, public, false)
}
pub fn create_room_with_policy(
    home: &Path,
    alias: &str,
    members: Vec<Member>,
    hours: u64,
    public: bool,
    require_automation: bool,
) -> Result<Signed<Room>> {
    create_room_with_operators(
        home,
        alias,
        members,
        hours,
        public,
        require_automation,
        None,
    )
}
pub fn create_room_with_operators(
    home: &Path,
    alias: &str,
    members: Vec<Member>,
    hours: u64,
    public: bool,
    require_automation: bool,
    operators: Option<crate::knowledge_abuse::OperatorClaims>,
) -> Result<Signed<Room>> {
    if !util::valid_alias(alias) || hours == 0 || hours > 168 {
        return Err(INVALID);
    }
    let _mutation = mutation_lock(home)?;
    let mut config = load(home)?;
    if let Some(old) = config.rooms.get(alias).cloned() {
        remember_operator_bindings(&mut config, &old)?;
    }
    let key = crypto::load_key(home)?;
    let own = key.public().to_peer_id().to_string();
    if !members.iter().any(|m| m.peer_id == own) {
        return Err(INVALID);
    }
    // Renewals inherit the admission policy. Omitting a new CLI flag must not
    // silently reopen a room that already requires an automation test.
    let require_automation = require_automation
        || config
            .rooms
            .get(alias)
            .is_some_and(|old| old.certificate.signed.knowledge_automation_required);
    let inherit_operators = operators.is_none();
    let mut operators = operators.or_else(|| {
        config
            .rooms
            .get(alias)
            .and_then(|old| old.certificate.signed.knowledge_operators.clone())
    });
    if inherit_operators && let Some(claims) = &mut operators {
        let current: BTreeSet<&str> = members
            .iter()
            .map(|member| member.peer_id.as_str())
            .collect();
        claims
            .bindings
            .retain(|peer, _| current.contains(peer.as_str()));
    }
    let (room_id, epoch) = if let Some(old) = config.rooms.get(alias) {
        if old.authority_peer_id != own || old.certificate.signed.public != public {
            return Err(INVALID);
        }
        (
            old.certificate.signed.room_id.clone(),
            old.certificate.signed.epoch.checked_add(1).ok_or(INVALID)?,
        )
    } else {
        (util::random_id(), 1)
    };
    let at = util::now();
    let room = Room {
        version: if operators.is_some() {
            4
        } else if require_automation {
            3
        } else if public {
            2
        } else {
            1
        },
        room_id,
        epoch,
        issued_at: at,
        expires_at: at + hours * 3600,
        policy_id: Scanner::policy_id(),
        members,
        public,
        knowledge_automation_required: require_automation,
        knowledge_operators: operators,
    };
    let cert = Signed {
        signature: crypto::sign(&key, "idobata.room.v1", &room)?,
        public_key: crypto::public(&key),
        signed: room,
    };
    let trusted = TrustedRoom {
        authority_peer_id: own,
        certificate: cert.clone(),
    };
    crypto::validate_room(&trusted, &Scanner::policy_id(), at)?;
    remember_operator_bindings(&mut config, &trusted)?;
    config.rooms.insert(alias.into(), trusted);
    save(home, &config)?;
    Ok(cert)
}
pub fn join_room(home: &Path, alias: &str, cert: Signed<Room>, authority: &str) -> Result<()> {
    if !util::valid_alias(alias) {
        return Err(INVALID);
    }
    let _mutation = mutation_lock(home)?;
    let mut config = load(home)?;
    let own = crypto::load_key(home)?.public().to_peer_id().to_string();
    let trusted = TrustedRoom {
        authority_peer_id: authority.into(),
        certificate: cert,
    };
    crypto::validate_room(&trusted, &Scanner::policy_id(), util::now())?;
    if !trusted
        .certificate
        .signed
        .members
        .iter()
        .any(|m| m.peer_id == own)
    {
        return Err(INVALID);
    }
    if let Some(old) = config.rooms.get(alias) {
        if old.authority_peer_id != authority
            || old.certificate.signed.public != trusted.certificate.signed.public
            || (old.certificate.signed.knowledge_automation_required
                && !trusted.certificate.signed.knowledge_automation_required)
            || old.certificate.signed.room_id != trusted.certificate.signed.room_id
            || trusted.certificate.signed.epoch < old.certificate.signed.epoch
        {
            return Err(INVALID);
        }
        if trusted.certificate.signed.epoch == old.certificate.signed.epoch
            && util::canonical(&old.certificate)? != util::canonical(&trusted.certificate)?
        {
            return Err(INVALID);
        }
    }
    if let Some(old) = config.rooms.get(alias).cloned() {
        remember_operator_bindings(&mut config, &old)?;
    }
    remember_operator_bindings(&mut config, &trusted)?;
    config.rooms.insert(alias.into(), trusted);
    save(home, &config)
}

pub fn leave_room(home: &Path, alias: &str) -> Result<()> {
    let _mutation = mutation_lock(home)?;
    let mut config = load(home)?;
    let old = config.rooms.get(alias).cloned().ok_or(INVALID)?;
    remember_operator_bindings(&mut config, &old)?;
    config.rooms.remove(alias);
    save(home, &config)
}

#[cfg(test)]
mod operator_policy_tests {
    use super::*;
    use crate::knowledge_abuse::OperatorClaims;

    fn claims(members: &[Member], credit: u16) -> OperatorClaims {
        OperatorClaims {
            bindings: members
                .iter()
                .map(|member| (member.peer_id.clone(), "s21g".into()))
                .collect(),
            credits: BTreeMap::from([("s21g".into(), credit)]),
        }
    }

    #[cfg(unix)]
    #[test]
    fn mutation_lock_is_private_and_rejects_symbolic_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("issuer");
        let own = init(&home, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
        let lock = home.join("config.lock");
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let before = std::fs::read(home.join("config.json")).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"untouched").unwrap();
        std::fs::remove_file(&lock).unwrap();
        symlink(&outside, &lock).unwrap();
        assert!(create_room(&home, "room", vec![own], 1).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
        assert_eq!(std::fs::read(home.join("config.json")).unwrap(), before);
    }

    fn resign(home: &Path, room: Room) -> Signed<Room> {
        let key = crypto::load_key(home).unwrap();
        Signed {
            public_key: crypto::public(&key),
            signature: crypto::sign(&key, "idobata.room.v1", &room).unwrap(),
            signed: room,
        }
    }

    #[test]
    fn operators_are_signed_v4_sticky_and_do_not_change_legacy_certificates() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("issuer");
        let member = init(&home, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
        let legacy = create_room(&home, "room", vec![member.clone()], 1).unwrap();
        let bytes = util::canonical(&legacy).unwrap();
        assert_eq!(legacy.signed.version, 1);
        assert!(
            !serde_json::to_value(&legacy).unwrap()["signed"]
                .as_object()
                .unwrap()
                .contains_key("knowledge_operators")
        );
        let policy = claims(std::slice::from_ref(&member), 700);
        let gated = create_room_with_operators(
            &home,
            "room",
            vec![member.clone()],
            1,
            false,
            true,
            Some(policy.clone()),
        )
        .unwrap();
        assert_eq!(gated.signed.version, 4);
        assert_eq!(gated.signed.knowledge_operators, Some(policy.clone()));
        let renewed =
            create_room_with_policy(&home, "room", vec![member], 1, false, false).unwrap();
        assert!(renewed.signed.knowledge_automation_required);
        assert_eq!(renewed.signed.knowledge_operators, Some(policy));
        let decoded: Signed<Room> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(util::canonical(&decoded).unwrap(), bytes);
        crypto::validate_room(
            &TrustedRoom {
                authority_peer_id: crypto::load_key(&home)
                    .unwrap()
                    .public()
                    .to_peer_id()
                    .to_string(),
                certificate: decoded,
            },
            &Scanner::policy_id(),
            legacy.signed.issued_at,
        )
        .unwrap();
    }

    #[test]
    fn leave_and_rejoin_cannot_rebind_omit_downgrade_or_fork_history() {
        let root = tempfile::tempdir().unwrap();
        let issuer = root.path().join("issuer");
        let client = root.path().join("client");
        let members = vec![
            init(&issuer, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap(),
            init(&client, vec!["/ip4/127.0.0.1/tcp/39141".into()]).unwrap(),
        ];
        let cert = create_room_with_operators(
            &issuer,
            "room",
            members.clone(),
            1,
            false,
            true,
            Some(claims(&members, 1000)),
        )
        .unwrap();
        let authority = members[0].peer_id.clone();
        join_room(&client, "room", cert.clone(), &authority).unwrap();
        leave_room(&client, "room").unwrap();
        let saved = std::fs::read(client.join("config.json")).unwrap();
        let state = load(&client).unwrap();
        assert!(state.rooms.is_empty());
        assert!(
            state
                .knowledge_operator_history
                .contains_key(&cert.signed.room_id)
        );
        let mut changed = cert.signed.clone();
        changed.epoch += 1;
        let operators = changed.knowledge_operators.as_mut().unwrap();
        operators.credits.insert("other".into(), 1000);
        operators
            .bindings
            .insert(members[1].peer_id.clone(), "other".into());
        assert!(join_room(&client, "alias", resign(&issuer, changed), &authority).is_err());
        let mut omitted = cert.signed.clone();
        omitted.epoch += 1;
        omitted
            .knowledge_operators
            .as_mut()
            .unwrap()
            .bindings
            .remove(&members[1].peer_id);
        assert!(join_room(&client, "alias", resign(&issuer, omitted), &authority).is_err());
        let mut downgrade = cert.signed.clone();
        downgrade.epoch += 1;
        downgrade.version = 3;
        downgrade.knowledge_operators = None;
        assert!(join_room(&client, "alias", resign(&issuer, downgrade), &authority).is_err());
        let mut fork = cert.signed.clone();
        fork.knowledge_operators
            .as_mut()
            .unwrap()
            .credits
            .insert("s21g".into(), 500);
        assert!(join_room(&client, "alias", resign(&issuer, fork), &authority).is_err());
        assert_eq!(std::fs::read(client.join("config.json")).unwrap(), saved);
        let mut reduced = cert.signed.clone();
        reduced.epoch += 1;
        reduced
            .knowledge_operators
            .as_mut()
            .unwrap()
            .credits
            .insert("s21g".into(), 500);
        let reduced = resign(&issuer, reduced);
        join_room(&client, "alias", reduced.clone(), &authority).unwrap();
        join_room(&client, "alias", reduced, &authority).unwrap();
        leave_room(&client, "alias").unwrap();
        assert!(join_room(&client, "alias", cert.clone(), &authority).is_err());
        let unrelated = root.path().join("unrelated");
        let other = init(&unrelated, vec!["/ip4/127.0.0.1/tcp/39142".into()]).unwrap();
        let mut wrong_pin = cert.signed.clone();
        wrong_pin.epoch += 2;
        assert!(
            join_room(
                &client,
                "alias",
                resign(&unrelated, wrong_pin),
                &other.peer_id
            )
            .is_err()
        );
    }

    #[test]
    fn nonmember_bindings_and_invalid_credit_are_rejected_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("issuer");
        let member = init(&home, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
        let before = std::fs::read(home.join("config.json")).unwrap();
        let mut bad = claims(std::slice::from_ref(&member), 1000);
        bad.bindings.insert(
            identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id()
                .to_string(),
            "s21g".into(),
        );
        assert!(
            create_room_with_operators(
                &home,
                "room",
                vec![member.clone()],
                1,
                false,
                false,
                Some(bad)
            )
            .is_err()
        );
        assert!(
            create_room_with_operators(
                &home,
                "room",
                vec![member.clone()],
                1,
                false,
                false,
                Some(claims(&[member], 1001))
            )
            .is_err()
        );
        assert_eq!(std::fs::read(home.join("config.json")).unwrap(), before);
        let member = identity(&home, vec![]).unwrap();
        let cert = create_room_with_operators(
            &home,
            "room",
            vec![member.clone()],
            1,
            false,
            false,
            Some(claims(&[member], 1000)),
        )
        .unwrap();
        assert_eq!(cert.signed.version, 4);
        assert!(!cert.signed.knowledge_automation_required);
    }

    #[test]
    fn authority_wide_history_rejects_cross_room_rebinding_and_keeps_domains_separate() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("issuer");
        let own = init(&home, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
        let policy = claims(std::slice::from_ref(&own), 1000);
        create_room_with_operators(
            &home,
            "first",
            vec![own.clone()],
            1,
            false,
            false,
            Some(policy.clone()),
        )
        .unwrap();
        let second = create_room_with_operators(
            &home,
            "second",
            vec![own.clone()],
            1,
            false,
            false,
            Some(policy.clone()),
        )
        .unwrap();
        leave_room(&home, "first").unwrap();
        leave_room(&home, "second").unwrap();
        let before = std::fs::read(home.join("config.json")).unwrap();
        let different = OperatorClaims {
            bindings: BTreeMap::from([(own.peer_id.clone(), "other".into())]),
            credits: BTreeMap::from([("other".into(), 1000)]),
        };
        let omitted = OperatorClaims {
            bindings: BTreeMap::new(),
            credits: policy.credits.clone(),
        };
        for attempted in [different, omitted] {
            assert!(
                create_room_with_operators(
                    &home,
                    "third",
                    vec![own.clone()],
                    1,
                    false,
                    false,
                    Some(attempted),
                )
                .is_err()
            );
            assert_eq!(std::fs::read(home.join("config.json")).unwrap(), before);
        }
        let mut conflicting = load(&home).unwrap();
        conflicting
            .knowledge_operator_history
            .get_mut(&second.signed.room_id)
            .unwrap()
            .bindings
            .insert(own.peer_id.clone(), "other".into());
        assert!(save(&home, &conflicting).is_err());
        assert_eq!(std::fs::read(home.join("config.json")).unwrap(), before);
        util::atomic_write(
            &home.join("config.json"),
            &util::canonical(&conflicting).unwrap(),
        )
        .unwrap();
        assert!(load(&home).is_err());
        util::atomic_write(&home.join("config.json"), &before).unwrap();
        // Legacy rooms do not declare a contradictory operator binding.
        create_room(&home, "legacy", vec![own.clone()], 1).unwrap();
        let other_home = root.path().join("other-authority");
        let other = init(&other_home, vec!["/ip4/127.0.0.1/tcp/39141".into()]).unwrap();
        let members = vec![other.clone(), own.clone()];
        let different_domain = create_room_with_operators(
            &other_home,
            "external",
            members.clone(),
            1,
            false,
            false,
            Some(OperatorClaims {
                bindings: members
                    .iter()
                    .map(|member| (member.peer_id.clone(), "other".into()))
                    .collect(),
                credits: BTreeMap::from([("other".into(), 1000)]),
            }),
        )
        .unwrap();
        join_room(&home, "external", different_domain, &other.peer_id).unwrap();
        assert_eq!(load(&home).unwrap().knowledge_operator_history.len(), 3);
    }

    #[test]
    fn roster_removal_retains_binding_and_renewal_prunes_only_current_claims() {
        let root = tempfile::tempdir().unwrap();
        let issuer = root.path().join("issuer");
        let own = init(&issuer, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
        let removed = init(
            &root.path().join("removed"),
            vec!["/ip4/127.0.0.1/tcp/39141".into()],
        )
        .unwrap();
        let members = vec![own.clone(), removed.clone()];
        let original = create_room_with_operators(
            &issuer,
            "room",
            members.clone(),
            1,
            false,
            false,
            Some(claims(&members, 1000)),
        )
        .unwrap();
        let renewed = create_room_with_policy(&issuer, "room", vec![own], 1, false, false).unwrap();
        assert!(
            !renewed
                .signed
                .knowledge_operators
                .unwrap()
                .bindings
                .contains_key(&removed.peer_id)
        );
        assert_eq!(
            load(&issuer).unwrap().knowledge_operator_history[&original.signed.room_id].bindings
                [&removed.peer_id],
            "s21g"
        );
        let mut rebound = claims(&members, 1000);
        rebound.credits.insert("other".into(), 1000);
        rebound.bindings.insert(removed.peer_id, "other".into());
        let before = std::fs::read(issuer.join("config.json")).unwrap();
        assert!(
            create_room_with_operators(&issuer, "room", members, 1, false, false, Some(rebound))
                .is_err()
        );
        assert_eq!(std::fs::read(issuer.join("config.json")).unwrap(), before);
    }

    #[test]
    fn combined_history_size_is_rejected_before_config_atomic_write() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("issuer");
        let own = init(&home, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
        let before = std::fs::read(home.join("config.json")).unwrap();
        let mut config = load(&home).unwrap();
        let bindings: BTreeMap<String, String> = (0..HISTORY_PEERS)
            .map(|_| {
                (
                    identity::Keypair::generate_ed25519()
                        .public()
                        .to_peer_id()
                        .to_string(),
                    "g".repeat(128),
                )
            })
            .collect();
        for _ in 0..3 {
            config.knowledge_operator_history.insert(
                util::random_id(),
                OperatorBindingHistory {
                    authority_peer_id: own.peer_id.clone(),
                    epoch: 1,
                    certificate_digest: util::random_id(),
                    public: false,
                    automation_required: false,
                    required: true,
                    bindings: bindings.clone(),
                },
            );
        }
        assert!(util::canonical(&config).unwrap().len() > CONFIG_BYTES);
        assert!(save(&home, &config).is_err());
        assert_eq!(std::fs::read(home.join("config.json")).unwrap(), before);
        assert!(load(&home).is_ok());
    }

    #[test]
    fn full_history_rejects_new_bindings_and_rooms_without_eviction() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("issuer");
        let own = init(&home, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
        let cert = create_room_with_operators(
            &home,
            "room",
            vec![own.clone()],
            1,
            false,
            false,
            Some(claims(std::slice::from_ref(&own), 1000)),
        )
        .unwrap();
        let mut config = load(&home).unwrap();
        let history = config
            .knowledge_operator_history
            .get_mut(&cert.signed.room_id)
            .unwrap();
        for _ in 1..HISTORY_PEERS {
            history.bindings.insert(
                identity::Keypair::generate_ed25519()
                    .public()
                    .to_peer_id()
                    .to_string(),
                "s21g".into(),
            );
        }
        save(&home, &config).unwrap();
        let before = std::fs::read(home.join("config.json")).unwrap();
        let additional = init(
            &root.path().join("additional"),
            vec!["/ip4/127.0.0.1/tcp/39141".into()],
        )
        .unwrap();
        let members = vec![own.clone(), additional];
        assert!(
            create_room_with_operators(
                &home,
                "room",
                members.clone(),
                1,
                false,
                false,
                Some(claims(&members, 1000)),
            )
            .is_err()
        );
        assert_eq!(std::fs::read(home.join("config.json")).unwrap(), before);
        let history = config
            .knowledge_operator_history
            .get_mut(&cert.signed.room_id)
            .unwrap();
        history.bindings.retain(|peer, _| peer == &own.peer_id);
        let sample = history.clone();
        for _ in 1..HISTORY_ROOMS {
            config
                .knowledge_operator_history
                .insert(util::random_id(), sample.clone());
        }
        save(&home, &config).unwrap();
        let before = std::fs::read(home.join("config.json")).unwrap();
        assert!(
            create_room_with_operators(
                &home,
                "additional",
                vec![own.clone()],
                1,
                false,
                false,
                Some(claims(std::slice::from_ref(&own), 1000)),
            )
            .is_err()
        );
        assert_eq!(std::fs::read(home.join("config.json")).unwrap(), before);
        create_room(&home, "room", vec![own], 1).unwrap();
        assert_eq!(load(&home).unwrap().knowledge_operator_history.len(), 32);
    }
}

#[cfg(test)]
mod automation_policy_tests {
    use super::*;

    #[test]
    fn automation_policy_upgrades_are_signed_inherited_and_cannot_be_downgraded() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("issuer");
        let second = temporary.path().join("member");
        let a = init(&first, vec!["/ip4/127.0.0.1/tcp/39101".into()]).unwrap();
        let b = init(&second, vec!["/ip4/127.0.0.1/tcp/39102".into()]).unwrap();
        let members = vec![a.clone(), b];
        let old = create_room(&first, "exchange", members.clone(), 1).unwrap();
        assert_eq!(old.signed.version, 1);
        assert!(!old.signed.knowledge_automation_required);
        assert!(
            serde_json::to_value(&old.signed)
                .unwrap()
                .get("knowledge_automation_required")
                .is_none()
        );
        let gated =
            create_room_with_policy(&first, "exchange", members.clone(), 1, false, true).unwrap();
        assert_eq!(gated.signed.room_id, old.signed.room_id);
        assert_eq!(gated.signed.version, 3);
        assert!(gated.signed.knowledge_automation_required);
        join_room(&second, "exchange", gated.clone(), &a.peer_id).unwrap();
        let renewed = create_room_with_visibility(&first, "exchange", members, 1, false).unwrap();
        assert!(renewed.signed.knowledge_automation_required);
        assert_eq!(renewed.signed.version, 3);
        join_room(&second, "exchange", renewed.clone(), &a.peer_id).unwrap();

        let key = crypto::load_key(&first).unwrap();
        let mut downgrade = renewed;
        downgrade.signed.epoch += 1;
        downgrade.signed.version = 1;
        downgrade.signed.knowledge_automation_required = false;
        downgrade.signature = crypto::sign(&key, "idobata.room.v1", &downgrade.signed).unwrap();
        assert!(join_room(&second, "exchange", downgrade, &a.peer_id).is_err());
        assert!(
            load(&second).unwrap().rooms["exchange"]
                .certificate
                .signed
                .knowledge_automation_required
        );
    }

    #[test]
    fn public_automation_rooms_use_version_three_and_bind_the_policy_flag() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("node");
        let own = init(&home, vec!["/ip4/127.0.0.1/tcp/39101".into()]).unwrap();
        let cert =
            create_room_with_policy(&home, "public", vec![own.clone()], 1, true, true).unwrap();
        assert_eq!(cert.signed.version, 3);
        let mut room = load(&home).unwrap().rooms["public"].clone();
        room.certificate.signed.knowledge_automation_required = false;
        // Changing the policy without a new valid signature is never a renewal.
        assert!(crypto::validate_room(&room, &Scanner::policy_id(), util::now()).is_err());
        let legacy =
            create_room_with_visibility(&home, "legacy-public", vec![own], 1, true).unwrap();
        assert_eq!(legacy.signed.version, 2);
    }
}
