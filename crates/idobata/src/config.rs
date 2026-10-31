use crate::{
    crypto,
    error::{INVALID, Result, STORAGE},
    scanner::Scanner,
    types::*,
    util,
};
use libp2p::identity;
use rand::RngCore;
use std::{collections::BTreeMap, path::Path};
pub fn load(home: &Path) -> Result<Config> {
    util::protected(home)?;
    let p = home.join("config.json");
    util::protected(&p)?;
    let c: Config =
        serde_json::from_slice(&util::read_bounded(&p, 131072)?).map_err(|_| INVALID)?;
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
    Ok(c)
}
pub fn save(home: &Path, c: &Config) -> Result<()> {
    util::atomic_write(&home.join("config.json"), &util::canonical(c)?)
}
pub fn init(home: &Path, listen: Vec<String>) -> Result<Member> {
    if home.join("config.json").exists()
        || home.join("identity.key").exists()
        || home.join("storage.key").exists()
    {
        return Err(INVALID);
    }
    for a in &listen {
        crypto::address(a, true)?;
    }
    util::private_dir(home)?;
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
    if !util::valid_alias(alias) || hours == 0 || hours > 168 {
        return Err(INVALID);
    }
    let mut config = load(home)?;
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
        version: if require_automation {
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
    config.rooms.insert(alias.into(), trusted);
    save(home, &config)?;
    Ok(cert)
}
pub fn join_room(home: &Path, alias: &str, cert: Signed<Room>, authority: &str) -> Result<()> {
    if !util::valid_alias(alias) {
        return Err(INVALID);
    }
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
    config.rooms.insert(alias.into(), trusted);
    save(home, &config)
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
