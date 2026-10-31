use crate::{
    crypto,
    error::{INVALID, Result},
    util,
};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advertisement {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub roles: Vec<String>,
    pub advertised_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    #[serde(flatten)]
    pub advertisement: Advertisement,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub version: u32,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub peers: Vec<Peer>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub signed: Bootstrap,
    pub key_id: String,
    pub signature: String,
}
pub const ADDRESS: &str = "/dns4/idobata-peer.s21g.com/tcp/443/wss";
pub fn create(
    node: &identity::Keypair,
    authority: &identity::Keypair,
    revision: u64,
    at: u64,
) -> Result<Document> {
    let ad = Advertisement {
        peer_id: node.public().to_peer_id().to_string(),
        addresses: vec![ADDRESS.into()],
        roles: vec!["bootstrap".into()],
        advertised_at: at,
        expires_at: at + 600,
    };
    let peer = Peer {
        signature: crypto::sign(node, "idobata.advertisement.v1", &ad)?,
        advertisement: ad,
    };
    let signed = Bootstrap {
        version: 1,
        revision,
        issued_at: at,
        expires_at: at + 600,
        peers: vec![peer],
    };
    Ok(Document {
        key_id: util::hash(crypto::public(authority).as_bytes()),
        signature: crypto::sign(authority, "idobata.bootstrap.v1", &signed)?,
        signed,
    })
}
pub fn verify(
    doc: &Document,
    trusted: &str,
    at: u64,
    checkpoint: Option<&crate::publication::Checkpoint>,
) -> Result<crate::publication::Checkpoint> {
    let b = &doc.signed;
    if doc.key_id != util::hash(trusted.as_bytes())
        || b.version != 1
        || b.revision == 0
        || b.revision > 9_007_199_254_740_991
        || b.issued_at > at + 300
        || b.expires_at <= at
        || b.expires_at <= b.issued_at
        || b.expires_at - b.issued_at > 600
        || b.peers.len() > 32
    {
        return Err(INVALID);
    }
    crypto::verify(
        &crypto::public_key(trusted)?,
        "idobata.bootstrap.v1",
        b,
        &doc.signature,
    )?;
    let mut seen = BTreeSet::new();
    for peer in &b.peers {
        let ad = &peer.advertisement;
        if !seen.insert(&ad.peer_id)
            || ad.addresses != [ADDRESS]
            || ad.roles != ["bootstrap"]
            || ad.advertised_at > at + 300
            || ad.expires_at < b.expires_at
            || ad.expires_at <= ad.advertised_at
            || ad.expires_at - ad.advertised_at > 600
        {
            return Err(INVALID);
        }
        let id: libp2p::PeerId = ad.peer_id.parse().map_err(|_| INVALID)?;
        if id.as_ref().code() != 0 {
            return Err(INVALID);
        }
        let key =
            identity::PublicKey::try_decode_protobuf(id.as_ref().digest()).map_err(|_| INVALID)?;
        if key.key_type() != identity::KeyType::Ed25519 {
            return Err(INVALID);
        }
        crypto::verify(&key, "idobata.advertisement.v1", ad, &peer.signature)?;
    }
    let digest = util::hash(&util::canonical(b)?);
    if let Some(old) = checkpoint
        && (b.revision < old.revision || (b.revision == old.revision && digest != old.digest))
    {
        return Err(INVALID);
    }
    Ok(crate::publication::Checkpoint {
        revision: b.revision,
        digest,
        trust_revision: None,
        trust_digest: None,
    })
}
