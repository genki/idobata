use super::*;

const ANCHOR_MAGIC: &[u8] = b"idobata.ledger.minimum.v1\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Minimum {
    genesis_hash: String,
    height: u64,
    block_id: String,
    application_hash: String,
}

impl Node {
    pub fn checkpoint(&self) -> Option<&CommitCertificate> {
        self.state.checkpoint.as_ref()
    }
    fn minimum_path(&self) -> PathBuf {
        self.path.with_file_name("ledger-minimum.enc")
    }
    fn read_minimum(&self) -> Result<Option<Minimum>> {
        let path = self.minimum_path();
        if !path.exists() {
            return Ok(None);
        }
        util::protected(&path)?;
        let bytes = util::read_bounded(&path, 4096)?;
        if !bytes.starts_with(ANCHOR_MAGIC) || bytes.len() < ANCHOR_MAGIC.len() + 40 {
            return Err(STORAGE);
        }
        let start = ANCHOR_MAGIC.len();
        let cipher = XChaCha20Poly1305::new_from_slice(&self.storage_key).map_err(|_| STORAGE)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&bytes[start..start + 24]),
                    Payload {
                        msg: &bytes[start + 24..],
                        aad: self.genesis_hash.as_bytes(),
                    },
                )
                .map_err(|_| STORAGE)?,
        );
        Ok(Some(serde_json::from_slice(&plain).map_err(|_| STORAGE)?))
    }
    fn write_minimum(&self, cert: &CommitCertificate) -> Result<()> {
        let minimum = Minimum {
            genesis_hash: self.genesis_hash.clone(),
            height: cert.block.height,
            block_id: cert.block.id()?,
            application_hash: cert.block.next_application_hash.clone(),
        };
        if let Some(old) = self.read_minimum()?
            && (old.genesis_hash != minimum.genesis_hash
                || old.height > minimum.height
                || (old.height == minimum.height
                    && (old.block_id != minimum.block_id
                        || old.application_hash != minimum.application_hash)))
        {
            return Err(STORAGE);
        }
        let plain = Zeroizing::new(serde_json::to_vec(&minimum).map_err(|_| STORAGE)?);
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.storage_key).map_err(|_| STORAGE)?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: self.genesis_hash.as_bytes(),
                },
            )
            .map_err(|_| STORAGE)?;
        let mut bytes = ANCHOR_MAGIC.to_vec();
        bytes.extend(nonce);
        bytes.extend(encrypted);
        util::atomic_write(&self.minimum_path(), &bytes)
    }
    pub(super) fn verify_minimum(&self) -> Result<()> {
        let Some(anchor) = self.read_minimum()? else {
            return Ok(());
        };
        if anchor.genesis_hash != self.genesis_hash || self.height() <= anchor.height {
            return Err(STORAGE);
        }
        let cert = self
            .state
            .commits
            .iter()
            .chain(self.state.checkpoint.iter())
            .find(|c| c.block.height == anchor.height)
            .ok_or(STORAGE)?;
        if cert.block.id()? != anchor.block_id
            || cert.block.next_application_hash != anchor.application_hash
        {
            return Err(STORAGE);
        }
        Ok(())
    }
    /// Core first durably stores its complete verified application checkpoint.
    /// Anchor is written before pruning. Signing promises, locks and round survive.
    pub fn compact_at_head(
        &mut self,
        core_height: u64,
        core_root: &str,
    ) -> Result<CommitCertificate> {
        let cert = self
            .state
            .commits
            .last()
            .cloned()
            .or_else(|| self.state.checkpoint.clone())
            .ok_or(HOLD)?;
        self.verify_commit(&cert)?;
        if core_height != cert.block.height || core_root != cert.block.next_application_hash {
            return Err(INVALID);
        }
        self.verify_minimum()?;
        self.storage_blocked = true;
        self.write_minimum(&cert)?;
        let mut state = self.state.clone();
        state.checkpoint = Some(cert.clone());
        let cut = state.commits.len().saturating_sub(SYNC_TAIL_BLOCKS);
        state.commits.drain(..cut);
        self.install(state)?;
        self.storage_blocked = false;
        Ok(cert)
    }
    /// Authenticate a monotonic checkpoint transition before touching Core disk.
    pub fn checkpoint_admissible(&self, cert: &CommitCertificate) -> Result<()> {
        self.verify_commit(cert)?;
        if cert.block.height < self.height() {
            return Err(INVALID);
        }
        if cert.block.height == self.height() {
            self.check_block(&cert.block)?;
            if let Some(lock) = &self.state.lock
                && lock.block.id()? != cert.block.id()?
                && cert.round <= lock.round
            {
                return Err(INVALID);
            }
        }
        if let Some(old) = self.read_minimum()? {
            if old.genesis_hash != self.genesis_hash
                || old.height > cert.block.height
                || (old.height == cert.block.height
                    && (old.block_id != cert.block.id()?
                        || old.application_hash != cert.block.next_application_hash))
            {
                return Err(STORAGE);
            }
            if old.height >= self.height() && old.height != cert.block.height {
                return Err(STORAGE);
            }
            if old.height < self.height() {
                self.verify_minimum()?;
            }
        }
        Ok(())
    }
    /// A quorum-finalized higher height resolves lower-height signing work.
    /// Advance to H+1; never reset to the same/older signing height. Evidence is
    /// retained. Core snapshot is verified and durable before this method.
    pub fn import_checkpoint(
        &mut self,
        cert: CommitCertificate,
        core_height: u64,
        core_root: &str,
    ) -> Result<()> {
        self.checkpoint_admissible(&cert)?;
        if core_height != cert.block.height || core_root != cert.block.next_application_hash {
            return Err(INVALID);
        }
        self.storage_blocked = true;
        self.write_minimum(&cert)?;
        let mut state = self.state.clone();
        state.height = core_height.checked_add(1).ok_or(INVALID)?;
        state.round = 0;
        state.proposals.clear();
        state.votes.clear();
        state.timeouts.clear();
        state.round_certificate = None;
        state.lock = None;
        state.valid = None;
        state.checkpoint = Some(cert.clone());
        state.commits = vec![cert];
        self.install(state)?;
        self.storage_blocked = false;
        self.round_started = Instant::now();
        Ok(())
    }
}
