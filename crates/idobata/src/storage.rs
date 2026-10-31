use crate::{
    error::{Result, STORAGE},
    types::State,
    util,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::RngCore;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
const MAGIC: &[u8] = b"idobata.store.v1\0";
pub struct Storage {
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
}
impl Storage {
    pub fn open(home: &Path) -> Result<Self> {
        util::protected(home)?;
        let key_path = home.join("storage.key");
        util::protected(&key_path)?;
        let key = util::read_bounded(&key_path, 32)?;
        if key.len() != 32 {
            return Err(STORAGE);
        }
        Ok(Self {
            path: home.join("state.enc"),
            key,
        })
    }
    pub fn load(&self) -> Result<State> {
        if !self.path.exists() {
            return Ok(State {
                version: 1,
                ..State::default()
            });
        }
        util::protected(&self.path)?;
        let bytes = util::read_bounded(&self.path, 64 * 1024 * 1024)?;
        let offset = MAGIC.len();
        if bytes.len() < offset + 24 || &bytes[..offset] != MAGIC {
            return Err(STORAGE);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| STORAGE)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&bytes[offset..offset + 24]),
                    Payload {
                        msg: &bytes[offset + 24..],
                        aad: MAGIC,
                    },
                )
                .map_err(|_| STORAGE)?,
        );
        let state: State = serde_json::from_slice(&plain).map_err(|_| STORAGE)?;
        if state.version != 1
            || state.outbox.len() > 4096
            || state.inbox.len() > 4096
            || state.prepared.len() > 256
        {
            return Err(STORAGE);
        }
        Ok(state)
    }
    pub fn save(&self, state: &State) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(state).map_err(|_| STORAGE)?);
        if plain.len() > 63 * 1024 * 1024 {
            return Err(STORAGE);
        }
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| STORAGE)?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: MAGIC,
                },
            )
            .map_err(|_| STORAGE)?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(nonce);
        bytes.extend(encrypted);
        util::atomic_write(&self.path, &bytes)
    }
}
pub fn prune(state: &mut State, at: u64) {
    state.prepared.retain(|p| p.expires_at > at);
    state.inbox.retain(|m| m.received_at + 7 * 86400 > at);
    state.outbox.retain(|m| m.created_at + 7 * 86400 > at);
}
