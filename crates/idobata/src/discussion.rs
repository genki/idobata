use crate::{
    error::{INVALID, Result},
    types::*,
};

pub fn messages(state: &State, room_id: &str) -> Vec<Envelope> {
    let mut result = Vec::new();
    for wire in state
        .inbox
        .iter()
        .filter(|m| m.received_at.saturating_add(7 * 86400) > crate::util::now())
        .map(|m| &m.wire)
        .chain(
            state
                .outbox
                .iter()
                .filter(|m| m.created_at.saturating_add(7 * 86400) > crate::util::now())
                .map(|m| &m.wire),
        )
    {
        if let Ok(env) = serde_json::from_slice::<Envelope>(wire)
            && env.payload.room_id == room_id
            && !result
                .iter()
                .any(|e: &Envelope| e.payload.message_id == env.payload.message_id)
        {
            result.push(env);
        }
    }
    result.sort_by_key(|e| e.payload.created_at);
    result
}

pub fn validate(
    state: &State,
    room_id: &str,
    sender: &str,
    draft: &Draft,
    options: &PostOptions,
) -> Result<()> {
    let Some(parent_id) = &options.reply_to else {
        return if options.resolution.is_none() {
            Ok(())
        } else {
            Err(INVALID)
        };
    };
    let all = messages(state, room_id);
    let parent = all
        .iter()
        .find(|e| &e.payload.message_id == parent_id)
        .ok_or(INVALID)?;
    if options.public && !parent.payload.options.public {
        return Err(INVALID);
    }
    if options.resolution.is_some()
        && (parent.payload.kind != "question"
            || parent.payload.sender_peer_id != sender
            || draft.kind != "observation")
    {
        return Err(INVALID);
    }
    Ok(())
}

pub fn thread_root<'a>(all: &'a [Envelope], message: &'a Envelope) -> &'a str {
    let mut current = message;
    for _ in 0..64 {
        let Some(parent) = &current.payload.options.reply_to else {
            break;
        };
        let Some(found) = all.iter().find(|e| &e.payload.message_id == parent) else {
            break;
        };
        current = found;
    }
    &current.payload.message_id
}

pub fn render(all: &[Envelope], env: &Envelope) -> serde_json::Value {
    let p = &env.payload;
    let mut state = "open";
    if p.kind == "question" {
        for child in all {
            if child.payload.options.reply_to.as_ref() == Some(&p.message_id) {
                if let Some(action) = child.payload.options.resolution {
                    state = match action {
                        Resolution::Resolved => "resolved",
                        Resolution::Reopened => "open",
                    };
                } else if child.payload.kind == "answer" && state != "resolved" {
                    state = "answered";
                }
            }
        }
    }
    serde_json::json!({"message_id":p.message_id,"untrusted":true,"created_at":p.created_at,
        "kind":p.kind,"title":p.title,"body":p.body,"references":p.references,
        "public":p.options.public,"reply_to":p.options.reply_to,
        "thread_id":thread_root(all,env),"resolution":p.options.resolution,
        "question_state":if p.kind=="question" {Some(state)} else {None}})
}
