//! Bounded influence and resource policy for already authenticated knowledge.
//!
//! This module does not authenticate peers, signatures, room certificates or
//! operator independence. The caller MUST construct the registry only from a
//! verified room-authority policy and supply verified, correctly scoped evidence.
//! An authority's operator binding is a trust assumption, not a mathematical
//! proof of independent ownership or of a statement's truth. No environment,
//! secret, retrieval count or automation quiz result supplies reputation.
//!
//! Each external operator has at most one direct credit unit. Its five newest
//! other-record outcomes are averaged into at most one historical credit unit.
//! Feedback changes an author's small prior, never the registry's fixed credit.
//! Promotion requires three external positive operators, at least 3000 positive
//! credit units, and positive credit strictly exceeding negative credit. Thus a
//! two-operator coalition alone cannot promote a claim under correct bindings.
//!
//! The economic model at the end uses NONTRANSFERABLE ACCOUNTING UNITS ONLY.
//! It moves no currency, asserts no economic deterrence and adjudicates no truth.
//! A real caller would need durable atomic state and independently authenticated
//! decisions; reconstructing a model must not reset a live epoch's spent state.

use crate::knowledge_rating::{Evidence, Quality, search_score};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const FULL_CREDIT: u16 = 1000;
pub const MAX_POLICY_PEERS: usize = 32;
pub const MAX_POLICY_OPERATORS: usize = 32;
pub const REQUIRED_POSITIVE_GROUPS: usize = 3;
pub const REQUIRED_POSITIVE_CREDIT: u32 = 3000;
const HISTORY_RECORDS: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    InvalidId,
    TooManyPeers,
    TooManyOperators,
    InvalidCredit,
    MissingOperator,
    InvalidLimits,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

/// Unknown identities deliberately share one namespace and one resource bucket.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorGroup {
    Registered(String),
    Unknown,
}

/// This claim set must be covered by the room authority's signature. Merely
/// deserializing it does not establish authentication or independent ownership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorClaims {
    pub bindings: BTreeMap<String, String>,
    pub credits: BTreeMap<String, u16>,
}
impl OperatorClaims {
    pub fn validate(&self) -> Result<(), PolicyError> {
        OperatorRegistry::from_verified(self.bindings.clone(), self.credits.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Default)]
pub struct OperatorRegistry {
    bindings: BTreeMap<String, String>,
    credits: BTreeMap<String, u16>,
}

impl OperatorRegistry {
    /// Input authentication and historical key/group continuity are caller duties.
    /// Re-keying within an operator must preserve its ID, quotas and epoch state.
    pub fn from_verified(
        bindings: BTreeMap<String, String>,
        credits: BTreeMap<String, u16>,
    ) -> Result<Self, PolicyError> {
        if bindings.len() > MAX_POLICY_PEERS {
            return Err(PolicyError::TooManyPeers);
        }
        if credits.len() > MAX_POLICY_OPERATORS {
            return Err(PolicyError::TooManyOperators);
        }
        if credits.keys().any(|id| !valid_id(id))
            || bindings
                .iter()
                .any(|(peer, operator)| !valid_id(peer) || !valid_id(operator))
        {
            return Err(PolicyError::InvalidId);
        }
        if credits.values().any(|credit| *credit > FULL_CREDIT) {
            return Err(PolicyError::InvalidCredit);
        }
        if bindings.values().any(|group| !credits.contains_key(group)) {
            return Err(PolicyError::MissingOperator);
        }
        Ok(Self { bindings, credits })
    }

    pub fn group(&self, peer: &str) -> OperatorGroup {
        self.bindings
            .get(peer)
            .cloned()
            .map(OperatorGroup::Registered)
            .unwrap_or(OperatorGroup::Unknown)
    }

    pub fn credit(&self, group: &OperatorGroup) -> u16 {
        match group {
            OperatorGroup::Registered(id) => self.credits.get(id).copied().unwrap_or(0),
            OperatorGroup::Unknown => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Assessment {
    pub author_group: OperatorGroup,
    pub quality: Quality,
    pub positive_groups: usize,
    pub negative_groups: usize,
    /// Integer thousandths, not money or a calibrated probability.
    pub positive_weight: u32,
    pub negative_weight: u32,
    pub promoted: bool,
}

/// Signed-record origin and optional verified local authority history are
/// exclusion inputs, never reviewer-credit grants. Additional exclusions alone
/// do not register an otherwise unknown author or make legacy votes eligible.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorContext {
    pub historical_group: OperatorGroup,
    pub additional_exclusions: BTreeSet<OperatorGroup>,
}
impl Default for AuthorContext {
    fn default() -> Self {
        Self {
            historical_group: OperatorGroup::Unknown,
            additional_exclusions: BTreeSet::new(),
        }
    }
}

/// Caller verifies the historical certificate before supplying these claims.
/// Legacy reviews use Unknown/0; a later registration cannot retroactively add
/// voting rights. This module additionally enforces current binding continuity
/// and min(historical_credit, current_credit), separately for every statement.
#[derive(Clone, Debug)]
pub struct VerifiedEvidence {
    pub evidence: Evidence,
    pub historical_group: OperatorGroup,
    pub historical_credit: u16,
    /// Set only after validating a complete signed same-record fork proof.
    /// This suppresses this operator on this record, never the whole record.
    pub contested: bool,
}
impl std::ops::Deref for VerifiedEvidence {
    type Target = Evidence;
    fn deref(&self) -> &Evidence {
        &self.evidence
    }
}
impl std::ops::DerefMut for VerifiedEvidence {
    fn deref_mut(&mut self) -> &mut Evidence {
        &mut self.evidence
    }
}
fn effective_credit(registry: &OperatorRegistry, vote: &VerifiedEvidence) -> u16 {
    let current = registry.group(&vote.reviewer);
    if vote.contested
        || current == OperatorGroup::Unknown
        || current != vote.historical_group
        || vote.historical_credit > FULL_CREDIT
    {
        return 0;
    }
    registry.credit(&current).min(vote.historical_credit)
}

fn latest_votes<'a>(
    author: &str,
    evidence: &'a [VerifiedEvidence],
) -> Vec<(usize, &'a VerifiedEvidence)> {
    let mut latest: BTreeMap<(&str, &str), (usize, &VerifiedEvidence)> = BTreeMap::new();
    for (index, vote) in evidence
        .iter()
        .enumerate()
        .filter(|(_, v)| v.author == author)
    {
        let key = (vote.record_id.as_str(), vote.reviewer.as_str());
        if latest.get(&key).is_none_or(|(_, previous)| {
            (
                vote.sequence,
                vote.created_at,
                !vote.useful,
                vote.contested,
                u16::MAX - vote.historical_credit,
                vote.historical_group == OperatorGroup::Unknown,
            ) > (
                previous.sequence,
                previous.created_at,
                !previous.useful,
                previous.contested,
                u16::MAX - previous.historical_credit,
                previous.historical_group == OperatorGroup::Unknown,
            )
        }) {
            latest.insert(key, (index, vote));
        }
    }
    latest.into_values().collect()
}

#[derive(Clone)]
struct GroupVote {
    useful: bool,
    created_at: u64,
    credit: u16,
}

/// Latest per-peer claims collapse into one operator claim per record. Any
/// unresolved negative within that operator prevents its positive endorsement;
/// copying positive keys cannot outvote the operator's own contradictory claim.
fn group_votes(
    registry: &OperatorRegistry,
    author: &str,
    evidence: &[VerifiedEvidence],
    excluded_groups: &BTreeSet<OperatorGroup>,
) -> BTreeMap<(OperatorGroup, String), GroupVote> {
    let mut votes: BTreeMap<(OperatorGroup, String), GroupVote> = BTreeMap::new();
    for (_, vote) in latest_votes(author, evidence) {
        let group = registry.group(&vote.reviewer);
        let credit = effective_credit(registry, vote);
        if excluded_groups.contains(&group) || credit == 0 {
            continue;
        }
        votes
            .entry((group, vote.record_id.clone()))
            .and_modify(|old| {
                if old.useful == vote.useful {
                    old.credit = old.credit.max(credit);
                } else if !vote.useful {
                    old.useful = false;
                    old.credit = credit;
                }
                old.created_at = old.created_at.max(vote.created_at);
            })
            .or_insert(GroupVote {
                useful: vote.useful,
                created_at: vote.created_at,
                credit,
            });
    }
    votes
}

pub fn assess(
    registry: &OperatorRegistry,
    record_id: &str,
    author: &str,
    evidence: &[VerifiedEvidence],
) -> Assessment {
    assess_with_author_context(
        registry,
        record_id,
        author,
        evidence,
        &AuthorContext::default(),
    )
}

pub fn assess_with_author_context(
    registry: &OperatorRegistry,
    record_id: &str,
    author: &str,
    evidence: &[VerifiedEvidence],
    context: &AuthorContext,
) -> Assessment {
    AssessmentIndex::new(registry, author, evidence, context).assess(record_id)
}

/// Ephemeral, room/author/context-scoped index of already verified evidence.
/// Construct once per bounded query/admission batch, never a global cache. The
/// sixth history item suffices to exclude any target from its five-item prior.
pub struct AssessmentIndex {
    author_group: OperatorGroup,
    direct: BTreeMap<String, Vec<GroupVote>>,
    history: BTreeMap<OperatorGroup, Vec<(String, GroupVote)>>,
}
impl AssessmentIndex {
    pub fn new(
        registry: &OperatorRegistry,
        author: &str,
        evidence: &[VerifiedEvidence],
        context: &AuthorContext,
    ) -> Self {
        let current_group = registry.group(author);
        let author_group = if current_group != OperatorGroup::Unknown {
            current_group.clone()
        } else {
            context.historical_group.clone()
        };
        let mut excluded = context.additional_exclusions.clone();
        excluded.insert(current_group);
        excluded.insert(context.historical_group.clone());
        let votes = if author_group == OperatorGroup::Unknown {
            BTreeMap::new()
        } else {
            group_votes(registry, author, evidence, &excluded)
        };
        let mut direct: BTreeMap<String, Vec<GroupVote>> = BTreeMap::new();
        let mut history: BTreeMap<OperatorGroup, Vec<(String, GroupVote)>> = BTreeMap::new();
        for ((group, id), vote) in votes {
            direct.entry(id.clone()).or_default().push(vote.clone());
            history.entry(group).or_default().push((id, vote));
        }
        for records in history.values_mut() {
            records.sort_by(|(a_id, a), (b_id, b)| {
                b.created_at.cmp(&a.created_at).then_with(|| a_id.cmp(b_id))
            });
            records.truncate(HISTORY_RECORDS + 1);
        }
        Self {
            author_group,
            direct,
            history,
        }
    }

    pub fn assess(&self, record_id: &str) -> Assessment {
        let mut positive_groups = 0;
        let mut negative_groups = 0;
        let mut positive_weight = 0u32;
        let mut negative_weight = 0u32;
        if let Some(votes) = self.direct.get(record_id) {
            for vote in votes {
                if vote.useful {
                    positive_groups += 1;
                    positive_weight += u32::from(vote.credit);
                } else {
                    negative_groups += 1;
                    negative_weight += u32::from(vote.credit);
                }
            }
        }
        let mut historical_positive = 0.0;
        let mut historical_total = 0.0;
        for records in self.history.values() {
            let selected = records
                .iter()
                .filter(|(id, _)| id != record_id)
                .take(HISTORY_RECORDS)
                .collect::<Vec<_>>();
            for (_, vote) in &selected {
                let weight =
                    f64::from(vote.credit) / f64::from(FULL_CREDIT) / selected.len() as f64;
                if vote.useful {
                    historical_positive += weight;
                }
                historical_total += weight;
            }
        }
        let author_reputation = (2.0 + historical_positive) / (4.0 + historical_total);
        let prior_mean = 0.5 + 0.3 * (author_reputation - 0.5);
        let positive = f64::from(positive_weight) / f64::from(FULL_CREDIT);
        let negative = f64::from(negative_weight) / f64::from(FULL_CREDIT);
        let total = positive + negative;
        Assessment {
            author_group: self.author_group.clone(),
            quality: Quality {
                value: (2.0 * prior_mean + positive) / (2.0 + total),
                confidence: total / (total + 4.0),
                useful_votes: positive_groups,
                negative_votes: negative_groups,
                author_reputation,
            },
            positive_groups,
            negative_groups,
            positive_weight,
            negative_weight,
            promoted: self.author_group != OperatorGroup::Unknown
                && positive_groups >= REQUIRED_POSITIVE_GROUPS
                && positive_weight >= REQUIRED_POSITIVE_CREDIT
                && positive_weight > negative_weight,
        }
    }
}

/// Indices into one record's verified reviews, for the MAX_REVIEWERS boundary.
/// Retain the latest signed packet for EVERY current registered peer, including
/// same-operator peers: discarding them would discard sequence watermarks and
/// permit an old negative to reappear after that peer corrected it. A valid room
/// has <=32 members and forbids author self-reviews: a current author permits
/// <=31 current peer claims plus one unknown/legacy packet. A retired author can
/// have 32 current reviewers; those take all slots and unknown gets no slot.
/// Use limit=32 for persistence; a smaller projection loses the full watermark
/// retention guarantee. Scoring still
/// grants at most one credit unit per operator. Unknown claims never displace a
/// current peer. The spare unknown representative uses peer-ID-first ordering,
/// a monotone total order, rather than losing another unknown peer's watermark.
/// Apply this to existing+incoming reviews before enforcing packet count.
pub fn select_review_slots(
    registry: &OperatorRegistry,
    record_id: &str,
    author: &str,
    evidence: &[VerifiedEvidence],
    limit: usize,
) -> Vec<usize> {
    let own_group = registry.group(author);
    let mut known = Vec::new();
    let mut other: Option<(usize, &VerifiedEvidence)> = None;
    for (index, vote) in latest_votes(author, evidence) {
        if vote.record_id != record_id {
            continue;
        }
        let group = registry.group(&vote.reviewer);
        if group != OperatorGroup::Unknown {
            known.push((index, vote));
        } else if other.as_ref().is_none_or(|(_, old)| {
            (
                &vote.reviewer,
                vote.sequence,
                vote.created_at,
                !vote.useful,
                u16::MAX - vote.historical_credit,
            ) > (
                &old.reviewer,
                old.sequence,
                old.created_at,
                !old.useful,
                u16::MAX - old.historical_credit,
            )
        }) {
            other = Some((index, vote));
        }
    }
    known.sort_by_key(|(_, vote)| {
        let group = registry.group(&vote.reviewer);
        (
            !(group != own_group && effective_credit(registry, vote) > 0),
            group,
            vote.reviewer.clone(),
        )
    });
    let mut result = known
        .into_iter()
        .take(limit.min(MAX_POLICY_PEERS))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if result.len() < limit.min(MAX_POLICY_PEERS)
        && let Some((index, _)) = other
    {
        result.push(index);
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchMode {
    Normal,
    Explore,
}

#[derive(Clone, Copy, Debug)]
pub struct PoolLimits {
    pub total: usize,
    pub per_operator: usize,
    pub unconfirmed: usize,
    pub unconfirmed_per_operator: usize,
}
impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            total: 64,
            per_operator: 16,
            unconfirmed: 16,
            unconfirmed_per_operator: 2,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ExposureLimits {
    pub total: usize,
    pub unconfirmed: usize,
    pub unconfirmed_per_operator: usize,
}
impl Default for ExposureLimits {
    fn default() -> Self {
        Self {
            total: 20,
            unconfirmed: 2,
            unconfirmed_per_operator: 1,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RankedCandidate {
    pub id: String,
    pub author: String,
    pub group: OperatorGroup,
    pub assessment: Assessment,
    pub score: f64,
}
fn ranking(a: &RankedCandidate, b: &RankedCandidate) -> std::cmp::Ordering {
    a.assessment
        .promoted
        .cmp(&b.assessment.promoted)
        .then_with(|| a.score.total_cmp(&b.score))
        .then_with(|| b.id.cmp(&a.id))
}

/// Offer verified metadata before retaining remote bodies or truncating top-K.
/// A later better candidate replaces a worse candidate in a full group, so an
/// early spam arrival cannot permanently reserve that group's candidate slots.
pub struct CandidatePool {
    limits: PoolLimits,
    entries: BTreeMap<String, RankedCandidate>,
}
impl CandidatePool {
    pub fn new(limits: PoolLimits) -> Result<Self, PolicyError> {
        if limits.total == 0
            || limits.total > 1024
            || limits.per_operator == 0
            || limits.per_operator > limits.total
            || limits.unconfirmed > limits.total
            || limits.unconfirmed_per_operator > limits.per_operator
        {
            return Err(PolicyError::InvalidLimits);
        }
        Ok(Self {
            limits,
            entries: BTreeMap::new(),
        })
    }

    pub fn offer(
        &mut self,
        registry: &OperatorRegistry,
        id: &str,
        author: &str,
        relevance: f64,
        evidence: &[VerifiedEvidence],
    ) -> bool {
        self.offer_assessed(
            registry,
            id,
            author,
            relevance,
            assess(registry, id, author, evidence),
        )
    }

    /// Assessment MUST be recomputed locally from verified historical evidence;
    /// never pass a remote provider's advertised quality or promotion boolean.
    pub fn offer_assessed(
        &mut self,
        registry: &OperatorRegistry,
        id: &str,
        author: &str,
        relevance: f64,
        assessment: Assessment,
    ) -> bool {
        let current_group = registry.group(author);
        if !valid_id(id)
            || !valid_id(author)
            || !relevance.is_finite()
            || relevance <= 0.0
            || self.entries.get(id).is_some_and(|old| old.author != author)
            || (current_group != OperatorGroup::Unknown && current_group != assessment.author_group)
        {
            return false;
        }
        let candidate = RankedCandidate {
            id: id.into(),
            author: author.into(),
            group: assessment.author_group.clone(),
            score: search_score(relevance, &assessment.quality),
            assessment,
        };
        // An updated verified negative must not leave an obsolete promoted copy.
        self.entries.remove(id);
        let group = candidate.group.clone();
        let mut proposed = self.entries.clone();
        proposed.insert(id.into(), candidate);
        loop {
            let group_count = proposed.values().filter(|c| c.group == group).count();
            let group_low = proposed
                .values()
                .filter(|c| c.group == group && !c.assessment.promoted)
                .count();
            let total_low = proposed.values().filter(|c| !c.assessment.promoted).count();
            let restricted_group = group_count > self.limits.per_operator;
            let restricted_low_group = group_low > self.limits.unconfirmed_per_operator;
            let restricted_low = total_low > self.limits.unconfirmed;
            if !restricted_group
                && !restricted_low_group
                && !restricted_low
                && proposed.len() <= self.limits.total
            {
                break;
            }
            let victim = proposed
                .values()
                .filter(|c| {
                    (!restricted_group || c.group == group)
                        && (!restricted_low_group || (c.group == group && !c.assessment.promoted))
                        && (!restricted_low || !c.assessment.promoted)
                })
                .min_by(|a, b| ranking(a, b))
                .map(|c| c.id.clone());
            let Some(victim) = victim else {
                return false;
            };
            if victim == id {
                return false;
            }
            proposed.remove(&victim);
        }
        self.entries = proposed;
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Normal never fills missing promoted slots with unconfirmed content.
    /// Explore adds at most the absolute and per-operator unconfirmed caps.
    pub fn select(&self, mode: SearchMode, limits: ExposureLimits) -> Vec<RankedCandidate> {
        let mut candidates = self.entries.values().cloned().collect::<Vec<_>>();
        candidates.sort_by(|a, b| ranking(b, a));
        let mut low = 0;
        let mut per_group = BTreeMap::new();
        let mut result = Vec::new();
        for candidate in candidates {
            if result.len() >= limits.total.min(1024) {
                break;
            }
            if !candidate.assessment.promoted {
                let count = per_group.entry(candidate.group.clone()).or_insert(0usize);
                if mode == SearchMode::Normal
                    || low >= limits.unconfirmed
                    || *count >= limits.unconfirmed_per_operator
                {
                    continue;
                }
                low += 1;
                *count += 1;
            }
            result.push(candidate);
        }
        result
    }
}

#[derive(Clone, Copy, Debug)]
pub struct QuotaLimits {
    pub total_bytes: u64,
    pub unconfirmed_bytes: u64,
    pub operator_unconfirmed_bytes: u64,
    pub unknown_unconfirmed_bytes: u64,
}
impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            total_bytes: 64 << 20,
            unconfirmed_bytes: 16 << 20,
            operator_unconfirmed_bytes: 2 << 20,
            unknown_unconfirmed_bytes: 1 << 20,
        }
    }
}
#[derive(Clone, Debug)]
pub struct StorageItem {
    pub id: String,
    pub author: String,
    pub bytes: u64,
    pub staging: bool,
    pub promoted: bool,
    pub priority: f64,
}
#[derive(Clone, Debug)]
pub struct IncomingStorage {
    pub id: String,
    pub author: String,
    pub bytes: u64,
    pub promoted: bool,
    pub priority: f64,
}

/// Resource attribution only. Body/certificate/index bytes belong to the
/// author's verified origin; each signed review/proof belongs to its reviewer
/// or demonstrated conflict operator. Metadata always uses the SAME low-trust
/// pool, even when the associated body is promoted.
#[derive(Clone, Debug)]
pub struct StorageCharge {
    pub group: OperatorGroup,
    pub bytes: u64,
    pub unconfirmed: bool,
}

fn charge_totals(
    charges: &[StorageCharge],
) -> Result<(u64, u64, BTreeMap<OperatorGroup, u64>), QuotaHold> {
    let mut total = 0u64;
    let mut low = 0u64;
    let mut groups = BTreeMap::new();
    for charge in charges {
        total = total.checked_add(charge.bytes).ok_or(QuotaHold::Overflow)?;
        if charge.unconfirmed {
            low = low.checked_add(charge.bytes).ok_or(QuotaHold::Overflow)?;
            let count = groups.entry(charge.group.clone()).or_insert(0u64);
            *count = count.checked_add(charge.bytes).ok_or(QuotaHold::Overflow)?;
        }
    }
    Ok((total, low, groups))
}

/// No eviction is performed. Existing-body reclassification after a policy or
/// review update may be included in BOTH snapshots as a grandfathered baseline;
/// a new review's bytes must still be charged only to its own operator.
pub fn check_storage_charges(
    before: &[StorageCharge],
    after: &[StorageCharge],
    limits: QuotaLimits,
    grandfather_existing: bool,
) -> Result<(), QuotaHold> {
    if limits.total_bytes == 0
        || limits.unconfirmed_bytes > limits.total_bytes
        || limits.operator_unconfirmed_bytes > limits.unconfirmed_bytes
        || limits.unknown_unconfirmed_bytes > limits.unconfirmed_bytes
    {
        return Err(QuotaHold::InvalidInput);
    }
    let (_, old_low, old_groups) = charge_totals(before)?;
    let (total, low, groups) = charge_totals(after)?;
    if total > limits.total_bytes {
        return Err(QuotaHold::ProtectedCapacity);
    }
    let low_limit = if grandfather_existing {
        limits.unconfirmed_bytes.max(old_low)
    } else {
        limits.unconfirmed_bytes
    };
    if low > low_limit {
        return Err(QuotaHold::LowTrustCapacity);
    }
    for (group, bytes) in groups {
        let base = if group == OperatorGroup::Unknown {
            limits.unknown_unconfirmed_bytes
        } else {
            limits.operator_unconfirmed_bytes
        };
        let limit = if grandfather_existing {
            base.max(old_groups.get(&group).copied().unwrap_or(0))
        } else {
            base
        };
        if bytes > limit {
            return Err(QuotaHold::LowTrustCapacity);
        }
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuotaHold {
    InvalidInput,
    Overflow,
    DuplicateId,
    ProtectedCapacity,
    LowTrustCapacity,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionDecision {
    pub accepted: bool,
    pub evict: Vec<String>,
    pub hold: Option<QuotaHold>,
}
impl AdmissionDecision {
    fn held(reason: QuotaHold) -> Self {
        Self {
            accepted: false,
            evict: vec![],
            hold: Some(reason),
        }
    }
}

/// Preflight NEW record admission, before returning accepted or creating staging.
/// Apply evictions and the incoming record in one durable transaction. Existing
/// accepted staging is never a victim. Low-trust work can evict only lower/equal
/// priority low-trust records in its OWN operator bucket, never another operator
/// or promoted data. Promoted work may reclaim non-staging low-trust data only.
pub fn check_storage_admission(
    registry: &OperatorRegistry,
    items: &[StorageItem],
    incoming: &IncomingStorage,
    limits: QuotaLimits,
) -> AdmissionDecision {
    let groups = items
        .iter()
        .map(|item| (item.id.clone(), registry.group(&item.author)))
        .chain(std::iter::once((
            incoming.id.clone(),
            registry.group(&incoming.author),
        )))
        .collect();
    check_storage_admission_with_groups(items, incoming, limits, &groups)
}

/// Record-ID -> verified origin group, including retired authors' signed record
/// certificates. Missing origins share Unknown. Caller verifies these bindings;
/// a key rotation must not open an unknown quota beside its existing operator.
pub fn check_storage_admission_with_groups(
    items: &[StorageItem],
    incoming: &IncomingStorage,
    limits: QuotaLimits,
    groups: &BTreeMap<String, OperatorGroup>,
) -> AdmissionDecision {
    let group_of = |id: &str| groups.get(id).cloned().unwrap_or(OperatorGroup::Unknown);
    if limits.total_bytes == 0
        || limits.unconfirmed_bytes > limits.total_bytes
        || limits.operator_unconfirmed_bytes > limits.unconfirmed_bytes
        || limits.unknown_unconfirmed_bytes > limits.unconfirmed_bytes
        || !valid_id(&incoming.id)
        || !valid_id(&incoming.author)
        || incoming.bytes == 0
        || !incoming.priority.is_finite()
        || groups
            .values()
            .any(|group| matches!(group,OperatorGroup::Registered(id) if !valid_id(id)))
    {
        return AdmissionDecision::held(QuotaHold::InvalidInput);
    }
    let mut ids = BTreeSet::new();
    if items.iter().any(|item| !ids.insert(&item.id)) {
        return AdmissionDecision::held(QuotaHold::InvalidInput);
    }
    if ids.contains(&incoming.id) {
        return AdmissionDecision::held(QuotaHold::DuplicateId);
    }
    let group = group_of(&incoming.id);
    let group_limit = if group == OperatorGroup::Unknown {
        limits.unknown_unconfirmed_bytes
    } else {
        limits.operator_unconfirmed_bytes
    };
    let mut total = incoming.bytes;
    let mut low = if incoming.promoted { 0 } else { incoming.bytes };
    let mut own_low = low;
    for item in items {
        let Some(next) = total.checked_add(item.bytes) else {
            return AdmissionDecision::held(QuotaHold::Overflow);
        };
        total = next;
        if !item.promoted {
            let Some(next) = low.checked_add(item.bytes) else {
                return AdmissionDecision::held(QuotaHold::Overflow);
            };
            low = next;
            if group_of(&item.id) == group {
                let Some(next) = own_low.checked_add(item.bytes) else {
                    return AdmissionDecision::held(QuotaHold::Overflow);
                };
                own_low = next;
            }
        }
    }
    // A policy migration may leave grandfathered data over its new quota.
    // Do not turn the next unconfirmed admission into implicit data deletion.
    if !incoming.promoted
        && (total - incoming.bytes > limits.total_bytes
            || low - incoming.bytes > limits.unconfirmed_bytes
            || own_low - incoming.bytes > group_limit)
    {
        return AdmissionDecision::held(QuotaHold::LowTrustCapacity);
    }
    let fits = |total, low, own_low| {
        total <= limits.total_bytes
            && (incoming.promoted || (low <= limits.unconfirmed_bytes && own_low <= group_limit))
    };
    let mut victims = items
        .iter()
        .filter(|item| {
            !item.staging
                && !item.promoted
                && item.priority.is_finite()
                && (incoming.promoted
                    || (group_of(&item.id) == group && item.priority <= incoming.priority))
        })
        .collect::<Vec<_>>();
    victims.sort_by(|a, b| {
        a.priority
            .total_cmp(&b.priority)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut evict = Vec::new();
    for item in victims {
        if fits(total, low, own_low) {
            break;
        }
        total -= item.bytes;
        low -= item.bytes;
        if group_of(&item.id) == group {
            own_low -= item.bytes;
        }
        evict.push(item.id.clone());
    }
    if fits(total, low, own_low) {
        AdmissionDecision {
            accepted: true,
            evict,
            hold: None,
        }
    } else {
        AdmissionDecision::held(if incoming.promoted {
            QuotaHold::ProtectedCapacity
        } else {
            QuotaHold::LowTrustCapacity
        })
    }
}

// Pure, bounded economic accounting model. These units are not currency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochScope {
    pub network: String,
    pub room: String,
    pub epoch: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRequest {
    pub scope: EpochScope,
    pub question: String,
    pub attempt: String,
    pub peer: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetError {
    InvalidLimits,
    InvalidId,
    ScopeMismatch,
    UnknownOperator,
    AttemptLimit,
    Capacity,
    Overflow,
    UnknownAttempt,
    InvalidTransition,
    MintHold,
    QuestionSettled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptStart {
    New,
    Existing,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum AttemptState {
    Open,
    Reserved(u64),
    Committed(u64),
    Released,
}
#[derive(Clone, Debug)]
struct Attempt {
    operator: OperatorGroup,
    question: String,
    state: AttemptState,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub cap: u64,
    pub spent: u64,
    pub reserved: u64,
    pub attempt_fees: u64,
    pub attempts: usize,
}
pub struct EpochBudget {
    scope: EpochScope,
    cap: u64,
    fee: u64,
    per_operator_attempts: u32,
    spent: u64,
    reserved: u64,
    attempt_fees: u64,
    counts: BTreeMap<OperatorGroup, u32>,
    attempts: BTreeMap<String, Attempt>,
    settled_questions: BTreeSet<String>,
}
impl EpochBudget {
    pub fn new(
        scope: EpochScope,
        cap: u64,
        fee: u64,
        per_operator_attempts: u32,
    ) -> Result<Self, BudgetError> {
        if !valid_id(&scope.network) || !valid_id(&scope.room) {
            return Err(BudgetError::InvalidId);
        }
        if fee == 0 || fee > cap || per_operator_attempts == 0 || per_operator_attempts > 1024 {
            return Err(BudgetError::InvalidLimits);
        }
        Ok(Self {
            scope,
            cap,
            fee,
            per_operator_attempts,
            spent: 0,
            reserved: 0,
            attempt_fees: 0,
            counts: BTreeMap::new(),
            attempts: BTreeMap::new(),
            settled_questions: BTreeSet::new(),
        })
    }
    fn operator(
        &self,
        registry: &OperatorRegistry,
        request: &AttemptRequest,
    ) -> Result<OperatorGroup, BudgetError> {
        if request.scope != self.scope {
            return Err(BudgetError::ScopeMismatch);
        }
        if !valid_id(&request.question) || !valid_id(&request.attempt) || !valid_id(&request.peer) {
            return Err(BudgetError::InvalidId);
        }
        let group = registry.group(&request.peer);
        if group == OperatorGroup::Unknown {
            return Err(BudgetError::UnknownOperator);
        }
        Ok(group)
    }
    fn checked_attempt(
        &self,
        registry: &OperatorRegistry,
        request: &AttemptRequest,
    ) -> Result<&Attempt, BudgetError> {
        let group = self.operator(registry, request)?;
        let attempt = self
            .attempts
            .get(&request.attempt)
            .ok_or(BudgetError::UnknownAttempt)?;
        if attempt.operator != group || attempt.question != request.question {
            return Err(BudgetError::ScopeMismatch);
        }
        Ok(attempt)
    }
    fn room_for(&self, additional: u64) -> Result<(), BudgetError> {
        let total = self
            .spent
            .checked_add(self.reserved)
            .and_then(|v| v.checked_add(additional))
            .ok_or(BudgetError::Overflow)?;
        if total > self.cap {
            return Err(BudgetError::Capacity);
        }
        Ok(())
    }
    pub fn begin_attempt(
        &mut self,
        registry: &OperatorRegistry,
        request: &AttemptRequest,
    ) -> Result<AttemptStart, BudgetError> {
        let group = self.operator(registry, request)?;
        if self.attempts.contains_key(&request.attempt) {
            self.checked_attempt(registry, request)?;
            return Ok(AttemptStart::Existing);
        }
        if self.settled_questions.contains(&request.question) {
            return Err(BudgetError::QuestionSettled);
        }
        let count = self.counts.get(&group).copied().unwrap_or(0);
        if count >= self.per_operator_attempts {
            return Err(BudgetError::AttemptLimit);
        }
        self.room_for(self.fee)?;
        let spent = self
            .spent
            .checked_add(self.fee)
            .ok_or(BudgetError::Overflow)?;
        let fees = self
            .attempt_fees
            .checked_add(self.fee)
            .ok_or(BudgetError::Overflow)?;
        let next_count = count.checked_add(1).ok_or(BudgetError::Overflow)?;
        self.spent = spent;
        self.attempt_fees = fees;
        self.counts.insert(group.clone(), next_count);
        self.attempts.insert(
            request.attempt.clone(),
            Attempt {
                operator: group,
                question: request.question.clone(),
                state: AttemptState::Open,
            },
        );
        Ok(AttemptStart::New)
    }
    pub fn reserve(
        &mut self,
        registry: &OperatorRegistry,
        request: &AttemptRequest,
        units: u64,
    ) -> Result<(), BudgetError> {
        if units == 0 {
            return Err(BudgetError::InvalidLimits);
        }
        self.checked_attempt(registry, request)?;
        if self.settled_questions.contains(&request.question) {
            return Err(BudgetError::QuestionSettled);
        }
        match self.checked_attempt(registry, request)?.state {
            AttemptState::Reserved(old) if old == units => return Ok(()),
            AttemptState::Open => {}
            _ => return Err(BudgetError::InvalidTransition),
        }
        self.room_for(units)?;
        self.reserved = self
            .reserved
            .checked_add(units)
            .ok_or(BudgetError::Overflow)?;
        self.attempts.get_mut(&request.attempt).unwrap().state = AttemptState::Reserved(units);
        Ok(())
    }
    /// Commit only an independently authorized award decision. This method
    /// merely moves model units; it never infers guilt or truth from text.
    pub fn commit(
        &mut self,
        registry: &OperatorRegistry,
        request: &AttemptRequest,
        context: &MintContext,
        support: &[ScopedSupport],
    ) -> Result<(), BudgetError> {
        if context.scope != request.scope
            || context.question != request.question
            || context.attempt != request.attempt
        {
            return Err(BudgetError::ScopeMismatch);
        }
        let units = match self.checked_attempt(registry, request)?.state {
            AttemptState::Committed(_) => return Ok(()),
            AttemptState::Reserved(units) => units,
            _ => return Err(BudgetError::InvalidTransition),
        };
        if self.settled_questions.contains(&request.question) {
            return Err(BudgetError::QuestionSettled);
        }
        let mut effective_context = context.clone();
        effective_context
            .excluded_groups
            .insert(self.operator(registry, request)?);
        if mint_eligibility(registry, &effective_context, support) != MintEligibility::Eligible {
            return Err(BudgetError::MintHold);
        }
        let spent = self.spent.checked_add(units).ok_or(BudgetError::Overflow)?;
        let reserved = self
            .reserved
            .checked_sub(units)
            .ok_or(BudgetError::Overflow)?;
        if spent.checked_add(reserved).ok_or(BudgetError::Overflow)? > self.cap {
            return Err(BudgetError::Capacity);
        }
        self.spent = spent;
        self.reserved = reserved;
        self.attempts.get_mut(&request.attempt).unwrap().state = AttemptState::Committed(units);
        self.settled_questions.insert(request.question.clone());
        Ok(())
    }
    pub fn release(
        &mut self,
        registry: &OperatorRegistry,
        request: &AttemptRequest,
    ) -> Result<(), BudgetError> {
        let units = match self.checked_attempt(registry, request)?.state {
            AttemptState::Released => return Ok(()),
            AttemptState::Open => 0,
            AttemptState::Reserved(units) => units,
            _ => return Err(BudgetError::InvalidTransition),
        };
        self.reserved = self
            .reserved
            .checked_sub(units)
            .ok_or(BudgetError::Overflow)?;
        self.attempts.get_mut(&request.attempt).unwrap().state = AttemptState::Released;
        Ok(())
    }
    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            cap: self.cap,
            spent: self.spent,
            reserved: self.reserved,
            attempt_fees: self.attempt_fees,
            attempts: self.attempts.len(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MintContext {
    pub scope: EpochScope,
    pub question: String,
    pub attempt: String,
    /// Include asker, answer author, beneficiary and every known conflict group.
    pub excluded_groups: BTreeSet<OperatorGroup>,
}
#[derive(Clone, Debug)]
pub struct ScopedSupport {
    pub scope: EpochScope,
    pub question: String,
    pub attempt: String,
    pub reviewer: String,
    pub positive: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MintEligibility {
    Eligible,
    Hold,
}

/// Eligibility only, never a mint transaction. Caller authenticates the full
/// scope and all statements, and supplies ALL conflict identities as groups.
pub fn mint_eligibility(
    registry: &OperatorRegistry,
    context: &MintContext,
    support: &[ScopedSupport],
) -> MintEligibility {
    if !valid_id(&context.question)
        || !valid_id(&context.attempt)
        || !valid_id(&context.scope.network)
        || !valid_id(&context.scope.room)
    {
        return MintEligibility::Hold;
    }
    let mut groups: BTreeMap<OperatorGroup, bool> = BTreeMap::new();
    for vote in support {
        if vote.scope != context.scope
            || vote.question != context.question
            || vote.attempt != context.attempt
        {
            continue;
        }
        let group = registry.group(&vote.reviewer);
        if registry.credit(&group) == 0 || context.excluded_groups.contains(&group) {
            continue;
        }
        groups
            .entry(group)
            .and_modify(|v| *v &= vote.positive)
            .or_insert(vote.positive);
    }
    let mut positive = 0u32;
    let mut negative = 0u32;
    let mut positive_groups = 0;
    for (group, useful) in groups {
        if useful {
            positive_groups += 1;
            positive += u32::from(registry.credit(&group));
        } else {
            negative += u32::from(registry.credit(&group));
        }
    }
    if positive_groups >= REQUIRED_POSITIVE_GROUPS
        && positive >= REQUIRED_POSITIVE_CREDIT
        && positive > negative
    {
        MintEligibility::Eligible
    } else {
        MintEligibility::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> OperatorRegistry {
        let bindings = [
            ("author", "author-op"),
            ("friend-a", "friend-a-op"),
            ("friend-b", "friend-b-op"),
            ("honest-a", "honest-a-op"),
            ("honest-b", "honest-b-op"),
            ("honest-c", "honest-c-op"),
            ("author-alias", "author-op"),
        ];
        OperatorRegistry::from_verified(
            bindings
                .into_iter()
                .map(|(p, g)| (p.into(), g.into()))
                .collect(),
            bindings
                .into_iter()
                .map(|(_, g)| (g.into(), FULL_CREDIT))
                .collect(),
        )
        .unwrap()
    }
    fn vote(id: &str, reviewer: &str, useful: bool) -> VerifiedEvidence {
        let group = if reviewer == "friend-alias" {
            OperatorGroup::Registered("friend-a-op".into())
        } else {
            registry().group(reviewer)
        };
        VerifiedEvidence {
            evidence: Evidence {
                record_id: id.into(),
                author: "author".into(),
                reviewer: reviewer.into(),
                useful,
                sequence: 1,
                created_at: 1,
            },
            historical_group: group,
            historical_credit: FULL_CREDIT,
            contested: false,
        }
    }
    fn positive(id: &str) -> Vec<VerifiedEvidence> {
        ["honest-a", "honest-b", "honest-c"]
            .into_iter()
            .map(|p| vote(id, p, true))
            .collect()
    }
    fn item(id: &str, author: &str, bytes: u64, staging: bool, promoted: bool) -> StorageItem {
        StorageItem {
            id: id.into(),
            author: author.into(),
            bytes,
            staging,
            promoted,
            priority: 0.5,
        }
    }
    fn incoming(id: &str, author: &str, bytes: u64, promoted: bool) -> IncomingStorage {
        IncomingStorage {
            id: id.into(),
            author: author.into(),
            bytes,
            promoted,
            priority: 0.6,
        }
    }
    fn quota() -> QuotaLimits {
        QuotaLimits {
            total_bytes: 100,
            unconfirmed_bytes: 40,
            operator_unconfirmed_bytes: 20,
            unknown_unconfirmed_bytes: 10,
        }
    }
    fn scope() -> EpochScope {
        EpochScope {
            network: "test-network".into(),
            room: "test-room".into(),
            epoch: 7,
        }
    }
    fn attempt(id: &str) -> AttemptRequest {
        AttemptRequest {
            scope: scope(),
            question: "question".into(),
            attempt: id.into(),
            peer: "author".into(),
        }
    }
    fn mint_context(request: &AttemptRequest) -> MintContext {
        MintContext {
            scope: request.scope.clone(),
            question: request.question.clone(),
            attempt: request.attempt.clone(),
            excluded_groups: BTreeSet::from([OperatorGroup::Registered("author-op".into())]),
        }
    }
    fn support(request: &AttemptRequest) -> Vec<ScopedSupport> {
        ["honest-a", "honest-b", "honest-c"]
            .into_iter()
            .map(|p| ScopedSupport {
                scope: request.scope.clone(),
                question: request.question.clone(),
                attempt: request.attempt.clone(),
                reviewer: p.into(),
                positive: true,
            })
            .collect()
    }

    #[test]
    fn unknown_thousand_keys_are_one_zero_credit_bucket() {
        let registry = registry();
        let neutral = assess(&registry, "target", "author", &[]);
        let evidence = (0..1000)
            .map(|i| vote("target", &format!("unknown-{i}"), true))
            .collect::<Vec<_>>();
        assert_eq!(assess(&registry, "target", "author", &evidence), neutral);
        assert_eq!(registry.group("unknown-0"), registry.group("unknown-999"));
        assert_eq!(registry.credit(&OperatorGroup::Unknown), 0);
        let mut pool = CandidatePool::new(PoolLimits::default()).unwrap();
        for i in 0..1000 {
            pool.offer(
                &registry,
                &format!("record-{i}"),
                &format!("unknown-{i}"),
                1.0,
                &[],
            );
        }
        assert_eq!(pool.len(), 2);
        assert!(
            pool.select(SearchMode::Normal, ExposureLimits::default())
                .is_empty()
        );
        assert_eq!(
            pool.select(SearchMode::Explore, ExposureLimits::default())
                .len(),
            1
        );
    }

    #[test]
    fn thirty_two_same_operator_keys_cannot_self_endorse_or_mint() {
        let peers = (0..32).map(|i| format!("peer-{i}")).collect::<Vec<_>>();
        let registry = OperatorRegistry::from_verified(
            peers
                .iter()
                .map(|p| (p.clone(), "one-owner".into()))
                .collect(),
            BTreeMap::from([("one-owner".into(), FULL_CREDIT)]),
        )
        .unwrap();
        let evidence = peers
            .iter()
            .map(|p| {
                let mut v = vote("target", p, true);
                v.evidence.author = peers[0].clone();
                v
            })
            .collect::<Vec<_>>();
        let assessment = assess(&registry, "target", &peers[0], &evidence);
        assert_eq!(assessment.positive_groups, 0);
        assert_eq!(assessment.quality.value, 0.5);
        assert!(!assessment.promoted);
        let request = attempt("attempt");
        let context = mint_context(&request);
        let support = peers
            .iter()
            .map(|p| ScopedSupport {
                reviewer: p.clone(),
                ..support(&request)[0].clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            mint_eligibility(&registry, &context, &support),
            MintEligibility::Hold
        );
    }

    #[test]
    fn author_and_two_friends_cannot_promote_with_reputation_farming() {
        let registry = registry();
        let mut evidence = vec![
            vote("target", "author-alias", true),
            vote("target", "friend-a", true),
            vote("target", "friend-b", true),
        ];
        for i in 0..1000 {
            for peer in ["friend-a", "friend-b"] {
                evidence.push(vote(&format!("farm-{i}"), peer, true));
            }
        }
        let result = assess(&registry, "target", "author", &evidence);
        assert_eq!(result.positive_groups, 2);
        assert_eq!(result.positive_weight, 2000);
        assert!(!result.promoted);
        assert!((result.quality.author_reputation - (4.0 / 6.0)).abs() < 1e-12);
        assert_eq!(registry.credit(&registry.group("friend-a")), FULL_CREDIT);
    }

    #[test]
    fn history_is_five_newest_record_average_with_one_total_credit() {
        let registry = registry();
        let mut history = (0..5)
            .map(|i| {
                let mut v = vote(&format!("new-{i}"), "friend-a", false);
                v.created_at = 100 + i;
                v
            })
            .collect::<Vec<_>>();
        let expected = assess(&registry, "target", "author", &history);
        for i in 0..1000 {
            history.push(vote(&format!("old-{i}"), "friend-a", true));
        }
        assert_eq!(assess(&registry, "target", "author", &history), expected);
        assert!((expected.quality.author_reputation - 0.4).abs() < 1e-12);
        let mut direct = history;
        direct.push(vote("target", "friend-a", true));
        assert_eq!(
            assess(&registry, "target", "author", &direct)
                .quality
                .author_reputation,
            expected.quality.author_reputation
        );
    }

    #[test]
    fn credit_threshold_is_absolute_and_cannot_be_earned_by_votes() {
        let base = registry();
        let mut credits = base.credits.clone();
        for group in ["honest-a-op", "honest-b-op", "honest-c-op"] {
            credits.insert(group.into(), 100);
        }
        let registry = OperatorRegistry::from_verified(base.bindings, credits).unwrap();
        let result = assess(&registry, "target", "author", &positive("target"));
        assert_eq!(result.positive_groups, 3);
        assert_eq!(result.positive_weight, 300);
        assert!(!result.promoted);
    }

    #[test]
    fn minority_negative_brigade_does_not_veto_three_honest_groups() {
        let registry = registry();
        let clean = assess(&registry, "target", "author", &positive("target"));
        let mut evidence = positive("target");
        evidence.push(vote("target", "friend-a", false));
        evidence.push(vote("target", "friend-b", false));
        let attacked = assess(&registry, "target", "author", &evidence);
        assert!(clean.promoted && attacked.promoted);
        assert_eq!(attacked.negative_groups, 2);
        assert!(attacked.quality.value < clean.quality.value);
        let mut negative = vec![vote("target", "friend-a", false)];
        for i in 0..100 {
            negative.push(vote(&format!("past-{i}"), "honest-a", true));
        }
        assert!(
            assess(&registry, "target", "author", &negative)
                .quality
                .value
                < 0.5
        );
    }

    #[test]
    fn latest_sequence_forks_and_group_conflicts_are_deterministic() {
        let base = registry();
        let mut bindings = base.bindings;
        bindings.insert("friend-alias".into(), "friend-a-op".into());
        let registry = OperatorRegistry::from_verified(bindings, base.credits).unwrap();
        let old = vote("target", "friend-a", true);
        let mut changed = old.clone();
        changed.sequence = 2;
        changed.useful = false;
        let mut stale = old.clone();
        stale.created_at = 999;
        let evidence = vec![old, changed, stale, vote("target", "friend-alias", true)];
        let a = assess(&registry, "target", "author", &evidence);
        let mut reversed = evidence.clone();
        reversed.reverse();
        assert_eq!(a, assess(&registry, "target", "author", &reversed));
        assert_eq!(a.negative_groups, 1);
        assert_eq!(a.positive_groups, 0);
        let positive = vote("target", "honest-a", true);
        let mut fork = positive.clone();
        fork.useful = false;
        assert_eq!(
            assess(&registry, "target", "author", &[positive, fork]).negative_groups,
            1
        );
    }

    #[test]
    fn review_slot_spam_cannot_displace_trusted_groups_or_duplicate_group_credit() {
        let registry = registry();
        let mut votes = (0..1000)
            .map(|i| vote("target", &format!("unknown-{i}"), true))
            .collect::<Vec<_>>();
        votes.extend(positive("target"));
        votes.push(vote("different-record", "friend-a", true));
        let selected = select_review_slots(&registry, "target", "author", &votes, 3);
        assert_eq!(selected.len(), 3);
        assert!(
            selected.iter().all(
                |index| registry.credit(&registry.group(&votes[*index].reviewer)) == FULL_CREDIT
            )
        );
        assert_eq!(
            select_review_slots(&registry, "target", "author", &votes, 32).len(),
            4
        );
    }

    #[test]
    fn honest_newcomer_is_preserved_for_bounded_explicit_exploration() {
        let registry = registry();
        let mut pool = CandidatePool::new(PoolLimits::default()).unwrap();
        assert!(pool.offer(&registry, "novice", "author", 1.0, &[]));
        let normal = pool.select(SearchMode::Normal, ExposureLimits::default());
        assert!(normal.is_empty());
        let explore = pool.select(SearchMode::Explore, ExposureLimits::default());
        assert_eq!(explore.len(), 1);
        assert_eq!(explore[0].id, "novice");
        assert!(!explore[0].assessment.promoted);
        for i in 0..20 {
            pool.offer(&registry, &format!("friend-{i}"), "friend-a", 1.0, &[]);
        }
        let explore = pool.select(SearchMode::Explore, ExposureLimits::default());
        assert_eq!(explore.len(), 2);
        assert_ne!(explore[0].group, explore[1].group);
    }

    #[test]
    fn candidate_flood_never_evicts_promoted_and_later_better_candidates_replace_spam() {
        let registry = registry();
        let limits = PoolLimits {
            total: 2,
            per_operator: 2,
            unconfirmed: 2,
            unconfirmed_per_operator: 2,
        };
        let mut pool = CandidatePool::new(limits).unwrap();
        assert!(pool.offer(&registry, "promoted", "author", 0.1, &positive("promoted")));
        for i in 0..1000 {
            pool.offer(
                &registry,
                &format!("spam-{i}"),
                &format!("unknown-{i}"),
                1.0,
                &[],
            );
        }
        let normal = pool.select(SearchMode::Normal, ExposureLimits::default());
        assert_eq!(normal.len(), 1);
        assert_eq!(normal[0].id, "promoted");
        let mut pool = CandidatePool::new(PoolLimits {
            total: 2,
            per_operator: 2,
            unconfirmed: 2,
            unconfirmed_per_operator: 1,
        })
        .unwrap();
        assert!(pool.offer(&registry, "early", "author", 0.1, &[]));
        assert!(pool.offer(&registry, "later", "author", 1.0, &[]));
        assert_eq!(
            pool.select(SearchMode::Explore, ExposureLimits::default())[0].id,
            "later"
        );
        assert!(!pool.offer(&registry, "nan", "author", f64::NAN, &[]));
    }

    #[test]
    fn newly_verified_negative_evidence_does_not_leave_stale_promoted_candidate() {
        let registry = registry();
        let mut pool = CandidatePool::new(PoolLimits::default()).unwrap();
        pool.offer(&registry, "target", "author", 1.0, &positive("target"));
        let evidence = [vote("target", "friend-a", false)];
        pool.offer(&registry, "target", "author", 1.0, &evidence);
        assert!(
            pool.select(SearchMode::Normal, ExposureLimits::default())
                .is_empty()
        );
    }

    #[test]
    fn quota_spam_cannot_evict_staging_promoted_or_other_operator_records() {
        let registry = registry();
        let records = [
            item("promoted", "honest-a", 60, false, true),
            item("staging", "author", 20, true, false),
            item("other", "friend-a", 20, false, false),
        ];
        let decision = check_storage_admission(
            &registry,
            &records,
            &incoming("spam", "author", 1, false),
            quota(),
        );
        assert!(!decision.accepted);
        assert!(decision.evict.is_empty());
        let records = [
            item("old-own", "author", 20, false, false),
            item("other", "friend-a", 20, false, false),
            item("promoted", "honest-a", 60, false, true),
        ];
        let decision = check_storage_admission(
            &registry,
            &records,
            &incoming("new", "author-alias", 20, false),
            quota(),
        );
        assert!(decision.accepted);
        assert_eq!(decision.evict, vec!["old-own"]);
    }

    #[test]
    fn quota_unknown_keys_share_cap_and_promoted_can_reclaim_only_lowtrust() {
        let registry = registry();
        let unknown = [item("unknown-old", "unknown-a", 10, true, false)];
        let decision = check_storage_admission(
            &registry,
            &unknown,
            &incoming("unknown-new", "unknown-b", 1, false),
            quota(),
        );
        assert!(!decision.accepted);
        let records = [
            item("promoted", "honest-a", 80, false, true),
            item("low", "friend-a", 20, false, false),
        ];
        let decision = check_storage_admission(
            &registry,
            &records,
            &incoming("good", "author", 20, true),
            quota(),
        );
        assert!(decision.accepted);
        assert_eq!(decision.evict, vec!["low"]);
        let protected = [item("staging", "author", 100, true, false)];
        assert!(
            !check_storage_admission(
                &registry,
                &protected,
                &incoming("good", "author", 1, true),
                quota()
            )
            .accepted
        );
    }

    #[test]
    fn quota_overflow_and_invalid_registry_fail_closed() {
        let registry = registry();
        let records = [item("huge", "author", u64::MAX, false, true)];
        assert_eq!(
            check_storage_admission(
                &registry,
                &records,
                &incoming("new", "author", 1, false),
                quota()
            )
            .hold,
            Some(QuotaHold::Overflow)
        );
        assert!(matches!(
            OperatorRegistry::from_verified(
                BTreeMap::from([("p".into(), "".into())]),
                BTreeMap::new()
            ),
            Err(PolicyError::InvalidId)
        ));
        assert!(matches!(
            OperatorRegistry::from_verified(BTreeMap::new(), BTreeMap::from([("g".into(), 1001)])),
            Err(PolicyError::InvalidCredit)
        ));
        let peers = (0..33).map(|i| (format!("p{i}"), "g".into())).collect();
        assert!(matches!(
            OperatorRegistry::from_verified(peers, BTreeMap::from([("g".into(), 1000)])),
            Err(PolicyError::TooManyPeers)
        ));
        assert!(matches!(
            OperatorRegistry::from_verified(
                BTreeMap::new(),
                (0..33).map(|i| (format!("g{i}"), 1)).collect()
            ),
            Err(PolicyError::TooManyOperators)
        ));
        assert!(matches!(
            OperatorRegistry::from_verified(
                BTreeMap::from([("p".into(), "missing".into())]),
                BTreeMap::new()
            ),
            Err(PolicyError::MissingOperator)
        ));
    }

    #[test]
    fn epoch_reservation_commit_release_preserves_cap_and_nonrefundable_attempt_fee() {
        let registry = registry();
        let mut budget = EpochBudget::new(scope(), 100, 3, 5).unwrap();
        let a = attempt("a");
        assert_eq!(budget.begin_attempt(&registry, &a), Ok(AttemptStart::New));
        assert_eq!(
            budget.begin_attempt(&registry, &a),
            Ok(AttemptStart::Existing)
        );
        budget.reserve(&registry, &a, 90).unwrap();
        budget.reserve(&registry, &a, 90).unwrap();
        let before = budget.snapshot();
        assert_eq!(
            budget.commit(&registry, &a, &mint_context(&a), &[]),
            Err(BudgetError::MintHold)
        );
        assert_eq!(budget.snapshot(), before);
        budget.release(&registry, &a).unwrap();
        budget.release(&registry, &a).unwrap();
        assert_eq!(budget.snapshot().spent, 3);
        assert_eq!(budget.snapshot().reserved, 0);
        assert_eq!(
            budget.reserve(&registry, &a, 1),
            Err(BudgetError::InvalidTransition)
        );
        let b = attempt("b");
        budget.begin_attempt(&registry, &b).unwrap();
        budget.reserve(&registry, &b, 94).unwrap();
        budget
            .commit(&registry, &b, &mint_context(&b), &support(&b))
            .unwrap();
        budget
            .commit(&registry, &b, &mint_context(&b), &support(&b))
            .unwrap();
        assert_eq!(
            budget.snapshot(),
            BudgetSnapshot {
                cap: 100,
                spent: 100,
                reserved: 0,
                attempt_fees: 6,
                attempts: 2
            }
        );
        assert_eq!(
            budget.begin_attempt(&registry, &attempt("c")),
            Err(BudgetError::QuestionSettled)
        );
    }

    #[test]
    fn rerolls_and_key_rotation_consume_same_operator_attempt_allowance() {
        let registry = registry();
        let mut budget = EpochBudget::new(scope(), 100, 1, 2).unwrap();
        let a = attempt("a");
        budget.begin_attempt(&registry, &a).unwrap();
        budget.release(&registry, &a).unwrap();
        let mut b = attempt("b");
        b.peer = "author-alias".into();
        budget.begin_attempt(&registry, &b).unwrap();
        budget.release(&registry, &b).unwrap();
        assert_eq!(
            budget.begin_attempt(&registry, &attempt("new-nonce")),
            Err(BudgetError::AttemptLimit)
        );
        assert_eq!(budget.snapshot().attempt_fees, 2);
        assert_eq!(budget.snapshot().spent, 2);
    }

    #[test]
    fn attempt_scope_question_and_operator_cannot_be_reused() {
        let registry = registry();
        let mut budget = EpochBudget::new(scope(), 100, 1, 10).unwrap();
        let a = attempt("same");
        budget.begin_attempt(&registry, &a).unwrap();
        let unchanged = budget.snapshot();
        for variant in 0..4 {
            let mut bad = a.clone();
            match variant {
                0 => bad.scope.epoch += 1,
                1 => bad.scope.room = "other".into(),
                2 => bad.question = "other".into(),
                _ => bad.peer = "friend-a".into(),
            };
            assert_eq!(
                budget.begin_attempt(&registry, &bad),
                Err(BudgetError::ScopeMismatch)
            );
            assert_eq!(
                budget.reserve(&registry, &bad, 1),
                Err(BudgetError::ScopeMismatch)
            );
        }
        assert_eq!(budget.snapshot(), unchanged);
        let mut bad = a.clone();
        bad.peer = "unknown".into();
        assert_eq!(
            budget.begin_attempt(&registry, &bad),
            Err(BudgetError::UnknownOperator)
        );
    }

    #[test]
    fn budget_checked_overflow_never_partially_reserves_or_spends() {
        let registry = registry();
        let mut budget = EpochBudget::new(scope(), u64::MAX, 1, 10).unwrap();
        let a = attempt("a");
        budget.begin_attempt(&registry, &a).unwrap();
        budget.reserve(&registry, &a, u64::MAX - 1).unwrap();
        let before = budget.snapshot();
        let mut b = attempt("b");
        b.question = "new-question".into();
        assert_eq!(
            budget.begin_attempt(&registry, &b),
            Err(BudgetError::Overflow)
        );
        assert_eq!(budget.snapshot(), before);
        budget
            .commit(&registry, &a, &mint_context(&a), &support(&a))
            .unwrap();
        assert_eq!(budget.snapshot().spent, u64::MAX);
        assert_eq!(budget.snapshot().reserved, 0);
        assert_eq!(
            budget.begin_attempt(&registry, &b),
            Err(BudgetError::Overflow)
        );
    }

    #[test]
    fn mint_holds_for_conflicts_insufficient_credit_and_replayed_scope() {
        let registry = registry();
        let request = attempt("award");
        let mut context = mint_context(&request);
        let mut votes = support(&request);
        assert_eq!(
            mint_eligibility(&registry, &context, &votes),
            MintEligibility::Eligible
        );
        context.excluded_groups.insert(registry.group("honest-a"));
        assert_eq!(
            mint_eligibility(&registry, &context, &votes),
            MintEligibility::Hold
        );
        context = mint_context(&request);
        votes[0].scope.epoch += 1;
        assert_eq!(
            mint_eligibility(&registry, &context, &votes),
            MintEligibility::Hold
        );
        votes = support(&request);
        votes[0].question = "other-question".into();
        assert_eq!(
            mint_eligibility(&registry, &context, &votes),
            MintEligibility::Hold
        );
        votes = support(&request);
        votes[0].attempt = "other-attempt".into();
        assert_eq!(
            mint_eligibility(&registry, &context, &votes),
            MintEligibility::Hold
        );
        let mut credits = registry.credits.clone();
        for g in ["honest-a-op", "honest-b-op", "honest-c-op"] {
            credits.insert(g.into(), 100);
        }
        let weak = OperatorRegistry::from_verified(registry.bindings.clone(), credits).unwrap();
        assert_eq!(
            mint_eligibility(&weak, &context, &support(&request)),
            MintEligibility::Hold
        );
        votes = support(&request);
        let mut dissent = votes[0].clone();
        dissent.positive = false;
        votes.push(dissent);
        assert_eq!(
            mint_eligibility(&registry, &context, &votes),
            MintEligibility::Hold
        );
    }

    #[test]
    fn historical_credit_is_per_statement_and_legacy_or_rebound_keys_gain_no_retroactive_rights() {
        let registry = registry();
        let mut evidence = positive("target");
        evidence[0].historical_credit = 100;
        let old = assess(&registry, "target", "author", &evidence);
        assert_eq!(old.positive_weight, 2100);
        assert!(!old.promoted);
        evidence[0].historical_group = OperatorGroup::Unknown;
        assert_eq!(
            assess(&registry, "target", "author", &evidence).positive_weight,
            2000
        );
        evidence[0].historical_group = OperatorGroup::Registered("different-owner".into());
        assert_eq!(
            assess(&registry, "target", "author", &evidence).positive_weight,
            2000
        );
        evidence[0].historical_group = registry.group("honest-a");
        evidence[0].historical_credit = 1000;
        let mut credits = registry.credits.clone();
        credits.insert("honest-a-op".into(), 100);
        let reduced = OperatorRegistry::from_verified(registry.bindings.clone(), credits).unwrap();
        assert_eq!(
            assess(&reduced, "target", "author", &evidence).positive_weight,
            2100
        );
    }

    #[test]
    fn old_weak_votes_do_not_dilute_new_valid_operator_credit_or_inflate_negative_credit() {
        let base = registry();
        let mut bindings = base.bindings;
        bindings.insert("new-key".into(), "honest-a-op".into());
        let registry = OperatorRegistry::from_verified(bindings, base.credits).unwrap();
        let mut evidence = positive("target");
        evidence[0].historical_credit = 100;
        let mut fresh = vote("target", "new-key", true);
        fresh.historical_group = registry.group("new-key");
        evidence.push(fresh);
        assert!(assess(&registry, "target", "author", &evidence).promoted);
        evidence[0].evidence.useful = false;
        let result = assess(&registry, "target", "author", &evidence);
        assert_eq!(result.positive_weight, 2000);
        assert_eq!(result.negative_weight, 100);
    }

    #[test]
    fn exact_claim_duplicate_cannot_launder_a_weaker_historical_certificate() {
        let registry = registry();
        let strong = vote("target", "honest-a", true);
        let mut weak = strong.clone();
        weak.historical_credit = 100;
        let a = assess(
            &registry,
            "target",
            "author",
            &[strong.clone(), weak.clone()],
        );
        let b = assess(&registry, "target", "author", &[weak, strong]);
        assert_eq!(a, b);
        assert_eq!(a.positive_weight, 100);
    }

    #[test]
    fn policy_quota_reduction_grandfathers_existing_records_and_rejects_new_lowtrust() {
        let registry = registry();
        let items = [
            item("old-a", "author", 15, false, false),
            item("old-b", "author-alias", 15, false, false),
        ];
        let result = check_storage_admission(
            &registry,
            &items,
            &incoming("new", "author", 1, false),
            quota(),
        );
        assert!(!result.accepted);
        assert!(result.evict.is_empty());
    }

    #[test]
    fn a_question_cannot_pay_twice_via_concurrent_attempts_or_reroll() {
        let registry = registry();
        let mut budget = EpochBudget::new(scope(), 100, 1, 10).unwrap();
        let a = attempt("a");
        let b = attempt("b");
        for request in [&a, &b] {
            budget.begin_attempt(&registry, request).unwrap();
            budget.reserve(&registry, request, 10).unwrap();
        }
        budget
            .commit(&registry, &a, &mint_context(&a), &support(&a))
            .unwrap();
        let before = budget.snapshot();
        assert_eq!(
            budget.commit(&registry, &b, &mint_context(&b), &support(&b)),
            Err(BudgetError::QuestionSettled)
        );
        assert_eq!(budget.snapshot(), before);
        assert_eq!(
            budget.begin_attempt(&registry, &attempt("reroll")),
            Err(BudgetError::QuestionSettled)
        );
        budget.release(&registry, &b).unwrap();
        assert_eq!(budget.snapshot().spent, 12);
        assert_eq!(budget.snapshot().reserved, 0);
    }

    #[test]
    fn budget_commit_excludes_attempt_operator_even_if_caller_omits_it() {
        let registry = registry();
        let mut budget = EpochBudget::new(scope(), 100, 1, 10).unwrap();
        let request = attempt("a");
        budget.begin_attempt(&registry, &request).unwrap();
        budget.reserve(&registry, &request, 10).unwrap();
        let mut context = mint_context(&request);
        context.excluded_groups.clear();
        let mut votes = support(&request);
        for (vote, peer) in votes.iter_mut().zip(["author", "friend-a", "friend-b"]) {
            vote.reviewer = peer.into();
        }
        let before = budget.snapshot();
        assert_eq!(
            budget.commit(&registry, &request, &context, &votes),
            Err(BudgetError::MintHold)
        );
        assert_eq!(budget.snapshot(), before);
    }

    #[test]
    fn retaining_current_peer_sequences_prevents_replayed_negative_resurrection() {
        let base = registry();
        let mut bindings = base.bindings;
        bindings.insert("friend-alias".into(), "friend-a-op".into());
        let registry = OperatorRegistry::from_verified(bindings, base.credits).unwrap();
        let a1 = vote("target", "friend-a", false);
        let mut a2 = a1.clone();
        a2.sequence = 2;
        a2.useful = true;
        a2.created_at = 2;
        let b = vote("target", "friend-alias", false);
        let mut retained = Vec::new();
        for packet in [a1.clone(), a2.clone(), b.clone(), a1.clone()] {
            retained.push(packet);
            retained = select_review_slots(&registry, "target", "author", &retained, 32)
                .into_iter()
                .map(|i| retained[i].clone())
                .collect();
        }
        assert_eq!(retained.len(), 2);
        assert!(
            retained
                .iter()
                .any(|v| v.reviewer == "friend-a" && v.sequence == 2 && v.useful)
        );
        let mut reversed = vec![a1, b, a2];
        reversed.reverse();
        let canonical = select_review_slots(&registry, "target", "author", &reversed, 32)
            .into_iter()
            .map(|i| {
                (
                    reversed[i].reviewer.clone(),
                    reversed[i].sequence,
                    reversed[i].useful,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            canonical,
            retained
                .iter()
                .map(|v| (v.reviewer.clone(), v.sequence, v.useful))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn unknown_representative_is_monotone_under_replays_and_input_order() {
        let registry = registry();
        let a1 = vote("target", "unknown-a", false);
        let mut a2 = a1.clone();
        a2.sequence = 2;
        a2.useful = true;
        a2.created_at = 0;
        let b = vote("target", "unknown-b", true);
        let mut retained = Vec::new();
        for packet in [a1.clone(), a2.clone(), b.clone(), a1] {
            retained.push(packet);
            retained = select_review_slots(&registry, "target", "author", &retained, 32)
                .into_iter()
                .map(|i| retained[i].clone())
                .collect();
        }
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].reviewer, "unknown-b");
        let reverse = vec![b, a2];
        let selected = select_review_slots(&registry, "target", "author", &reverse, 32);
        assert_eq!(reverse[selected[0]].reviewer, retained[0].reviewer);
    }

    #[test]
    fn removed_author_historical_operator_cannot_endorse_its_own_prior_or_content() {
        let base = registry();
        let mut bindings = base.bindings;
        bindings.remove("author");
        let registry = OperatorRegistry::from_verified(bindings, base.credits).unwrap();
        let context = AuthorContext {
            historical_group: OperatorGroup::Registered("author-op".into()),
            additional_exclusions: BTreeSet::new(),
        };
        let mut votes = vec![vote("target", "author-alias", true)];
        for i in 0..20 {
            votes.push(vote(&format!("farm-{i}"), "author-alias", true));
        }
        let result = assess_with_author_context(&registry, "target", "author", &votes, &context);
        assert_eq!(result.author_group, context.historical_group);
        assert_eq!(result.positive_groups, 0);
        assert_eq!(result.quality.author_reputation, 0.5);
        assert!(!result.promoted);
        votes.extend(positive("target"));
        assert!(
            assess_with_author_context(&registry, "target", "author", &votes, &context).promoted
        );
        let mut pool = CandidatePool::new(PoolLimits::default()).unwrap();
        pool.offer_assessed(&registry, "target", "author", 1.0, result);
        assert_eq!(
            pool.select(SearchMode::Explore, ExposureLimits::default())[0].group,
            context.historical_group
        );
    }

    #[test]
    fn local_exclusion_history_cannot_register_unknown_author_or_grant_legacy_credit() {
        let registry = registry();
        let mut votes = positive("target");
        for vote in &mut votes {
            vote.evidence.author = "removed-unknown".into();
        }
        let context = AuthorContext {
            historical_group: OperatorGroup::Unknown,
            additional_exclusions: BTreeSet::from([registry.group("honest-a")]),
        };
        let result =
            assess_with_author_context(&registry, "target", "removed-unknown", &votes, &context);
        assert_eq!(result.author_group, OperatorGroup::Unknown);
        assert_eq!(result.positive_groups, 0);
        assert_eq!(result.quality.value, 0.5);
        assert!(!result.promoted);
    }

    #[test]
    fn retired_author_storage_is_charged_to_same_verified_operator_bucket() {
        let items = [item("old", "retired-key", 20, true, false)];
        let new = incoming("new", "new-key", 1, false);
        let groups = BTreeMap::from([
            (
                "old".into(),
                OperatorGroup::Registered("stable-owner".into()),
            ),
            (
                "new".into(),
                OperatorGroup::Registered("stable-owner".into()),
            ),
        ]);
        let result = check_storage_admission_with_groups(&items, &new, quota(), &groups);
        assert!(!result.accepted);
        assert!(result.evict.is_empty());
    }

    #[test]
    fn retired_author_with_thirty_two_current_reviewers_leaves_no_unknown_slot() {
        let peers = (0..32)
            .map(|i| format!("current-{i:02}"))
            .collect::<Vec<_>>();
        let registry = OperatorRegistry::from_verified(
            peers.iter().map(|p| (p.clone(), p.clone())).collect(),
            peers.iter().map(|p| (p.clone(), 1000)).collect(),
        )
        .unwrap();
        let mut votes = peers
            .iter()
            .map(|peer| VerifiedEvidence {
                evidence: Evidence {
                    record_id: "target".into(),
                    author: "retired-author".into(),
                    reviewer: peer.clone(),
                    useful: true,
                    sequence: 1,
                    created_at: 1,
                },
                historical_group: registry.group(peer),
                historical_credit: 1000,
                contested: false,
            })
            .collect::<Vec<_>>();
        let mut unknown = vote("target", "unknown-late", true);
        unknown.evidence.author = "retired-author".into();
        votes.push(unknown);
        let selected = select_review_slots(&registry, "target", "retired-author", &votes, 32);
        assert_eq!(selected.len(), 32);
        assert!(
            selected
                .iter()
                .all(|i| registry.group(&votes[*i].reviewer) != OperatorGroup::Unknown)
        );
        let context = AuthorContext {
            historical_group: OperatorGroup::Registered("retired-owner".into()),
            additional_exclusions: BTreeSet::new(),
        };
        assert!(
            assess_with_author_context(&registry, "target", "retired-author", &votes, &context)
                .promoted
        );
    }

    #[test]
    fn metadata_is_charged_to_reviewer_not_victim_and_cannot_evict_a_body() {
        let author = OperatorGroup::Registered("victim".into());
        let attacker = OperatorGroup::Registered("attacker".into());
        let before = vec![StorageCharge {
            group: author.clone(),
            bytes: 20,
            unconfirmed: true,
        }];
        let mut after = before.clone();
        after.push(StorageCharge {
            group: attacker.clone(),
            bytes: 20,
            unconfirmed: true,
        });
        assert_eq!(
            check_storage_charges(&before, &after, quota(), true),
            Ok(())
        );
        after.push(StorageCharge {
            group: attacker,
            bytes: 1,
            unconfirmed: true,
        });
        assert_eq!(
            check_storage_charges(&before, &after, quota(), true),
            Err(QuotaHold::LowTrustCapacity)
        );
        assert_eq!(before[0].bytes, 20);
    }

    #[test]
    fn body_and_metadata_share_one_lowtrust_pool_and_checked_capacity() {
        let a = OperatorGroup::Registered("a".into());
        let b = OperatorGroup::Registered("b".into());
        let c = OperatorGroup::Registered("c".into());
        let before = vec![
            StorageCharge {
                group: a,
                bytes: 20,
                unconfirmed: true,
            },
            StorageCharge {
                group: b,
                bytes: 20,
                unconfirmed: true,
            },
        ];
        let mut after = before.clone();
        after.push(StorageCharge {
            group: c,
            bytes: 1,
            unconfirmed: true,
        });
        assert_eq!(
            check_storage_charges(&before, &after, quota(), true),
            Err(QuotaHold::LowTrustCapacity)
        );
        let huge = [
            StorageCharge {
                group: OperatorGroup::Unknown,
                bytes: u64::MAX,
                unconfirmed: false,
            },
            StorageCharge {
                group: OperatorGroup::Unknown,
                bytes: 1,
                unconfirmed: false,
            },
        ];
        assert_eq!(
            check_storage_charges(&[], &huge, quota(), false),
            Err(QuotaHold::Overflow)
        );
    }

    #[test]
    fn contested_operator_has_zero_record_influence_without_vetoing_other_three() {
        let registry = registry();
        let mut votes = positive("target");
        let mut bad = vote("target", "friend-a", false);
        bad.contested = true;
        votes.push(bad);
        let result = assess(&registry, "target", "author", &votes);
        assert!(result.promoted);
        assert_eq!(result.negative_groups, 0);
        assert_eq!(result.positive_weight, 3000);
    }

    #[test]
    fn indexed_history_uses_latest_five_other_records_and_preserves_direct_votes() {
        let registry = registry();
        let mut votes = Vec::new();
        for i in 0..20 {
            let mut item = vote(&format!("record-{i:02}"), "honest-a", i >= 15);
            item.created_at = i;
            votes.push(item);
        }
        let index = AssessmentIndex::new(&registry, "author", &votes, &AuthorContext::default());
        let oldest = index.assess("record-00");
        assert_eq!(oldest.negative_groups, 1);
        assert!((oldest.quality.author_reputation - 0.6).abs() < 1e-12);
        let newest = index.assess("record-19");
        // Excluding the target must bring the sixth latest record into history.
        assert_eq!(newest.positive_groups, 1);
        assert!((newest.quality.author_reputation - 0.56).abs() < 1e-12);
        for vote in &votes {
            assert_eq!(
                index.assess(&vote.record_id),
                assess(&registry, &vote.record_id, "author", &votes)
            );
        }
    }
}
