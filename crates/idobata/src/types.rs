pub use idobata_scanner::{Draft, Finding, Report};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub peer_id: String,
    pub public_key: String,
    pub addresses: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Room {
    pub version: u32,
    pub room_id: String,
    pub epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub policy_id: String,
    pub members: Vec<Member>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub signed: T,
    pub public_key: String,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRoom {
    pub authority_peer_id: String,
    pub certificate: Signed<Room>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub endpoint: String,
    pub listen: Vec<String>,
    pub rooms: BTreeMap<String, TrustedRoom>,
    #[serde(default)]
    pub client_uids: Vec<u32>,
    #[serde(default)]
    pub socket_group: Option<u32>,
    #[serde(default)]
    pub client_sid: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub version: u32,
    pub message_id: String,
    pub sender_peer_id: String,
    pub room_id: String,
    pub membership_epoch: u64,
    pub policy_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub references: Vec<String>,
}
impl Payload {
    pub fn draft(&self) -> Draft {
        Draft {
            kind: self.kind.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
            references: self.references.clone(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload: Payload,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u32,
    pub room_id: String,
    pub message_id: String,
    pub payload_digest: String,
    pub receiver_peer_id: String,
    pub received_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub receipt: Receipt,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireResponse {
    Accepted { ack: Acknowledgement },
    Rejected { code: i32 },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Info,
    Begin,
    Scan {
        room: String,
        draft: Draft,
    },
    Prepare {
        room: String,
        draft: Draft,
    },
    Preview {
        prepared: String,
    },
    Post {
        room: String,
        draft: Option<Draft>,
        prepared: Option<String>,
        request_id: String,
    },
    Status {
        request_id: String,
    },
    Inbox {
        room: String,
        limit: usize,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub code: i32,
    pub result: serde_json::Value,
}
impl Reply {
    pub fn new(code: i32, result: serde_json::Value) -> Self {
        Self { code, result }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub id: String,
    pub owner: String,
    pub room: String,
    pub expires_at: u64,
    pub policy_id: String,
    pub draft: Draft,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outbox {
    pub request_id: String,
    pub owner: String,
    pub room_alias: String,
    pub wire: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub delivered: BTreeMap<String, Acknowledgement>,
    pub recipients: Vec<String>,
    pub held: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbox {
    pub id: String,
    pub wire: Vec<u8>,
    pub ack: Acknowledgement,
    pub received_at: u64,
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub outbox: Vec<Outbox>,
    pub inbox: Vec<Inbox>,
    pub prepared: Vec<Prepared>,
    pub rejected_count: u64,
}
