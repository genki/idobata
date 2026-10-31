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
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub knowledge_automation_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub knowledge_operators: Option<crate::knowledge_abuse::OperatorClaims>,
}
pub fn is_false(value: &bool) -> bool {
    !*value
}
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostOptions {
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
}
impl PostOptions {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Resolved,
    Reopened,
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
pub struct OperatorBindingHistory {
    pub authority_peer_id: String,
    pub epoch: u64,
    pub certificate_digest: String,
    pub public: bool,
    pub automation_required: bool,
    pub required: bool,
    pub bindings: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub endpoint: String,
    pub listen: Vec<String>,
    pub rooms: BTreeMap<String, TrustedRoom>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub knowledge_operator_history: BTreeMap<String, OperatorBindingHistory>,
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
    #[serde(default, skip_serializing_if = "PostOptions::is_empty")]
    pub options: PostOptions,
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
    KnowledgePublish {
        room: String,
        input: crate::knowledge::KnowledgeInput,
        public: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<crate::automation::AutomationAnswer>,
    },
    KnowledgeSearch {
        room: String,
        query: String,
        limit: usize,
        #[serde(default, skip_serializing_if = "is_false")]
        explore: bool,
    },
    KnowledgeGet {
        room: String,
        id: String,
    },
    KnowledgeEvaluate {
        room: String,
        id: String,
        input: crate::knowledge::ReviewInput,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<crate::automation::AutomationAnswer>,
    },
    KnowledgePeers {
        room: String,
        query: String,
        limit: usize,
        #[serde(default, skip_serializing_if = "is_false")]
        explore: bool,
    },
    KnowledgeStatus {
        room: Option<String>,
    },
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
        #[serde(default)]
        options: PostOptions,
    },
    Status {
        request_id: String,
    },
    Inbox {
        room: String,
        limit: usize,
    },
    Search {
        room: String,
        query: String,
        thread: Option<String>,
        limit: usize,
    },
    PublicSnapshot {
        room: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before: Option<String>,
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
    #[serde(default)]
    pub certificate: Option<TrustedRoom>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn knowledge_ipc_actions_remain_explicit_and_reject_unknown_fields() {
        let search =
            json!({"action":"knowledge_search","room":"engineering","query":"retry","limit":10});
        let request = serde_json::from_value::<Request>(search.clone()).unwrap();
        assert!(
            matches!(&request, Request::KnowledgeSearch { room, query, limit: 10, explore: false } if room == "engineering" && query == "retry")
        );
        assert_eq!(serde_json::to_value(request).unwrap(), search);
        for action in ["knowledge_search", "knowledge_peers"] {
            let explicit = json!({"action":action,"room":"engineering","query":"retry","limit":10,"explore":true});
            let request = serde_json::from_value::<Request>(explicit.clone()).unwrap();
            assert!(matches!(
                &request,
                Request::KnowledgeSearch { explore: true, .. }
                    | Request::KnowledgePeers { explore: true, .. }
            ));
            assert_eq!(serde_json::to_value(request).unwrap(), explicit);
        }
        let legacy_publish = json!({"action":"knowledge_publish","room":"engineering","public":false,"input":{"problem":"retry","solution":"backoff"}});
        let request = serde_json::from_value::<Request>(legacy_publish).unwrap();
        assert!(matches!(
            &request,
            Request::KnowledgePublish { proof: None, .. }
        ));
        assert!(
            serde_json::to_value(request)
                .unwrap()
                .get("proof")
                .is_none()
        );
        let mut unknown = search;
        unknown["include_private_rooms"] = true.into();
        assert!(serde_json::from_value::<Request>(unknown).is_err());
        assert!(
            serde_json::from_value::<Request>(json!({"action":"knowledge_get","id":"record"}))
                .is_err()
        );
        assert!(serde_json::from_value::<Request>(json!({"action":"knowledge_publish","room":"engineering","public":false,"input":{"problem":"retry","solution":"backoff","collect_environment":true}})).is_err());
        assert!(
            serde_json::from_value::<Request>(json!({"action":"knowledge_export_all"})).is_err()
        );
    }
}
