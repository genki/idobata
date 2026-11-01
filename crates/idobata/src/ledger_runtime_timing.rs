use super::*;
use std::cell::{Cell, RefCell};
pub(super) const CACHE_ENABLED: bool = true;
#[derive(Default)]
pub(super) struct Timings {
    records: Cell<u64>,
    hits: Cell<u64>,
    record_us: Cell<u64>,
    record_max_us: Cell<u64>,
    pub incoming: Sample,
    pub drive: Sample,
    pub response: Sample,
    pub actions: [Sample; 3],
}
#[derive(Default)]
pub(super) struct Sample {
    count: Cell<u64>,
    total_us: Cell<u64>,
    max_us: Cell<u64>,
}
impl Sample {
    pub fn observe(&self, started: Instant) {
        let us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.count.set(self.count.get().saturating_add(1));
        self.total_us.set(self.total_us.get().saturating_add(us));
        self.max_us.set(self.max_us.get().max(us));
    }
    fn json(&self) -> Value {
        json!({"count":self.count.get(),"total_us":self.total_us.get(),"max_us":self.max_us.get()})
    }
}
impl Timings {
    pub fn json(&self) -> Value {
        json!({"record_checks":self.records.get(),"record_cache_hits":self.hits.get(),"record_total_us":self.record_us.get(),"record_max_us":self.record_max_us.get(),"incoming":self.incoming.json(),"drive":self.drive.json(),"response":self.response.json(),"actions":self.actions.iter().map(Sample::json).collect::<Vec<_>>()})
    }
}
pub(super) type ValidationCache = RefCell<BTreeMap<(String, String), (Instant, u64)>>;
impl Active {
    pub(super) fn validate_record_cached(
        &self,
        record: &RecordPacket,
        room: &TrustedRoom,
    ) -> Result<()> {
        let started = Instant::now();
        let checked_at = util::now();
        crypto::validate_room(room, &Scanner::policy_id(), checked_at)?;
        self.timings
            .records
            .set(self.timings.records.get().saturating_add(1));
        // Complete packet bytes bind content, historical authority, signatures,
        // automation and operator evidence. The current certificate/policy is a
        // separate cache key; room() rechecks current authorization every action.
        let key = (
            util::hash(&util::canonical(record)?),
            util::hash(&util::canonical(room)?),
        );
        if CACHE_ENABLED
            && record.record.signed.created_at <= checked_at.saturating_add(300)
            && self
                .validation_cache
                .borrow()
                .get(&key)
                .is_some_and(|(until, prior_check)| {
                    *until > Instant::now() && *prior_check <= checked_at
                })
        {
            self.timings
                .hits
                .set(self.timings.hits.get().saturating_add(1));
            return Ok(());
        }
        let result = knowledge::validate_record(record, room, checked_at);
        let us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.timings
            .record_us
            .set(self.timings.record_us.get().saturating_add(us));
        self.timings
            .record_max_us
            .set(self.timings.record_max_us.get().max(us));
        if result.is_ok() && CACHE_ENABLED {
            let mut cache = self.validation_cache.borrow_mut();
            cache.retain(|_, (until, _)| *until > Instant::now());
            if cache.len() >= MAX_PROOFS
                && let Some(key) = cache.keys().next().cloned()
            {
                cache.remove(&key);
            }
            cache.insert(key, (Instant::now() + Duration::from_secs(30), checked_at));
        }
        result
    }
}
