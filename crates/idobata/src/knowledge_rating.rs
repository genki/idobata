//! Deterministic usefulness estimates for agent knowledge exchange.
//!
//! Callers supply feedback only after verifying its signature, room authority,
//! record author and applicable sequence rules. An accepted signature establishes
//! who made a claim; it does not establish that the claim is true. This module
//! never treats retrieval counts, an author's own claims or local environment
//! data as evidence of usefulness.
//!
//! Each reviewer gets one latest vote per record. Sequence takes precedence over
//! creation time; equally ordered contradictory forks conservatively count as a
//! negative vote. Author reputation uses other records, with a neutral Beta(2,2)
//! prior and at most five distinct records per reviewer. Content starts with only
//! two prior votes, whose mean is `0.5 + 0.3 * (reputation - 0.5)`. Consequently a
//! single direct negative vote outweighs even the strongest author prior.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const AUTHOR_RECORDS_PER_REVIEWER: usize = 5;
const UNRATED_DECAY_SECONDS: f64 = 30.0 * 86_400.0;

/// An already accepted, signed usefulness evaluation by another agent.
#[derive(Clone, Debug)]
pub struct Evidence {
    pub record_id: String,
    pub author: String,
    pub reviewer: String,
    pub useful: bool,
    pub sequence: u64,
    pub created_at: u64,
}

/// A posterior estimate, not a claim that the knowledge is objectively correct.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Quality {
    pub value: f64,
    pub confidence: f64,
    pub useful_votes: usize,
    pub negative_votes: usize,
    pub author_reputation: f64,
}

/// Estimate one record from accepted feedback, independently of input ordering.
///
/// Reputation excludes the record being rated to avoid counting its votes twice.
/// The five newest other records per reviewer contribute; creation time, sequence
/// and then record ID make selection deterministic. A single prolific reviewer
/// cannot increase their total reputational influence beyond five votes.
pub fn quality(record_id: &str, author: &str, evidence: &[Evidence]) -> Quality {
    let mut latest: BTreeMap<(&str, &str), &Evidence> = BTreeMap::new();
    for vote in evidence
        .iter()
        .filter(|vote| vote.author == author && vote.reviewer != author)
    {
        let key = (vote.record_id.as_str(), vote.reviewer.as_str());
        let replace = latest.get(&key).is_none_or(|previous| {
            (vote.sequence, vote.created_at, !vote.useful)
                > (previous.sequence, previous.created_at, !previous.useful)
        });
        if replace {
            latest.insert(key, vote);
        }
    }

    let mut useful_votes = 0;
    let mut negative_votes = 0;
    let mut by_reviewer: BTreeMap<&str, Vec<&Evidence>> = BTreeMap::new();
    for vote in latest.values() {
        if vote.record_id == record_id {
            if vote.useful {
                useful_votes += 1;
            } else {
                negative_votes += 1;
            }
        } else {
            by_reviewer.entry(&vote.reviewer).or_default().push(vote);
        }
    }

    let mut reputation_useful = 0;
    let mut reputation_votes = 0;
    for votes in by_reviewer.values_mut() {
        votes.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.sequence.cmp(&a.sequence))
                .then_with(|| a.record_id.cmp(&b.record_id))
        });
        for vote in votes.iter().take(AUTHOR_RECORDS_PER_REVIEWER) {
            reputation_votes += 1;
            reputation_useful += usize::from(vote.useful);
        }
    }

    let author_reputation = (2.0 + reputation_useful as f64) / (4.0 + reputation_votes as f64);
    let prior_mean = 0.5 + 0.3 * (author_reputation - 0.5);
    let direct_votes = (useful_votes + negative_votes) as f64;
    Quality {
        value: (2.0 * prior_mean + useful_votes as f64) / (2.0 + direct_votes),
        confidence: direct_votes / (direct_votes + 4.0),
        useful_votes,
        negative_votes,
        author_reputation,
    }
}

/// Capacity eviction priority, in [0,1], with no fixed age-based expiration.
///
/// Unrated items halve their priority after thirty days. Direct evidence gives
/// useful records an age-independent floor `value * confidence`; additional
/// freshness decays smoothly. Future timestamps are treated as age zero.
pub fn retention_priority(quality: &Quality, created_at: u64, now: u64) -> f64 {
    let value = unit(quality.value);
    let confidence = unit(quality.confidence);
    let age = now.saturating_sub(created_at) as f64;
    let freshness = 1.0 / (1.0 + age / UNRATED_DECAY_SECONDS);
    value * (confidence + (1.0 - confidence) * freshness)
}

/// Language-independent substring coverage of distinct whitespace query terms.
///
/// Basic Unicode case folding handles Unicode lowercase, sharp S, sigma, long S
/// and compatibility ligatures; it performs no locale-specific tokenization,
/// stemming or accent normalization. Problem/solution matches have full weight,
/// context-only matches weight 0.7. Empty queries browse all records equally.
pub fn lexical_relevance(problem: &str, solution: &str, context: &str, query: &str) -> f64 {
    let query = casefold(query);
    let terms: BTreeSet<&str> = query.split_whitespace().collect();
    if terms.is_empty() {
        return 1.0;
    }
    let problem = casefold(problem);
    let solution = casefold(solution);
    let context = casefold(context);
    let coverage: f64 = terms
        .iter()
        .map(|term| {
            if problem.contains(term) || solution.contains(term) {
                1.0
            } else if context.contains(term) {
                0.7
            } else {
                0.0
            }
        })
        .sum();
    coverage / terms.len() as f64
}

/// Rank relevant knowledge by usefulness, without giving unrelated records a hit.
///
/// The multiplicative factor `0.5 + 0.5 * value` keeps lexical relevance central
/// while useful content and the small, bounded author prior improve ranking.
pub fn search_score(relevance: f64, quality: &Quality) -> f64 {
    unit(relevance) * (0.5 + 0.5 * unit(quality.value))
}

fn unit(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn casefold(text: &str) -> String {
    let mut folded = String::with_capacity(text.len());
    for character in text.chars().flat_map(char::to_lowercase) {
        match character {
            'ß' => folded.push_str("ss"),
            'ς' => folded.push('σ'),
            'ſ' => folded.push('s'),
            'ﬀ' => folded.push_str("ff"),
            'ﬁ' => folded.push_str("fi"),
            'ﬂ' => folded.push_str("fl"),
            'ﬃ' => folded.push_str("ffi"),
            'ﬄ' => folded.push_str("ffl"),
            'ﬅ' | 'ﬆ' => folded.push_str("st"),
            _ => folded.push(character),
        }
    }
    folded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(record: &str, author: &str, reviewer: &str, useful: bool) -> Evidence {
        Evidence {
            record_id: record.into(),
            author: author.into(),
            reviewer: reviewer.into(),
            useful,
            sequence: 1,
            created_at: 1,
        }
    }

    fn history(reviewer: &str, count: usize, useful: bool) -> Vec<Evidence> {
        (0..count)
            .map(|index| vote(&format!("other-{index}"), "author", reviewer, useful))
            .collect()
    }

    #[test]
    fn unrated_records_start_neutral_and_self_endorsements_do_not_train_reputation() {
        let neutral = quality("target", "author", &[]);
        assert_eq!(neutral.value, 0.5);
        assert_eq!(neutral.author_reputation, 0.5);
        assert_eq!(neutral.confidence, 0.0);
        let mut own_votes = history("author", 50, true);
        own_votes.push(vote("target", "author", "author", true));
        assert_eq!(quality("target", "author", &own_votes), neutral);
    }

    #[test]
    fn sequence_precedes_time_and_duplicate_votes_count_once() {
        let old = vote("target", "author", "reviewer", true);
        let mut latest = old.clone();
        latest.sequence = 2;
        latest.useful = false;
        let mut late_old = old.clone();
        late_old.created_at = 1_000;
        let result = quality("target", "author", &[old.clone(), latest, old, late_old]);
        assert_eq!((result.useful_votes, result.negative_votes), (0, 1));
        assert_eq!(result.author_reputation, 0.5);
    }

    #[test]
    fn same_sequence_uses_time_and_exact_forks_prefer_negative_independent_of_order() {
        let positive = vote("target", "author", "reviewer", true);
        let mut later = positive.clone();
        later.created_at = 2;
        later.useful = false;
        assert_eq!(
            quality("target", "author", &[later, positive.clone()]).negative_votes,
            1
        );

        let mut negative = positive.clone();
        negative.useful = false;
        let forward = quality("target", "author", &[positive.clone(), negative.clone()]);
        let reverse = quality("target", "author", &[negative, positive]);
        assert_eq!(forward, reverse);
        assert_eq!(forward.negative_votes, 1);
    }

    #[test]
    fn one_reviewers_reputation_amplification_is_capped_at_five_distinct_records() {
        let five = quality("target", "author", &history("reviewer", 5, true));
        let thousand = quality("target", "author", &history("reviewer", 1_000, true));
        assert_eq!(five, thousand);
        let mut independent = history("reviewer", 5, true);
        independent.extend(history("another-reviewer", 5, true));
        assert!(
            quality("target", "author", &independent).author_reputation > five.author_reputation
        );
    }

    #[test]
    fn reputational_cap_selects_newest_records_and_is_order_independent() {
        let mut evidence = history("reviewer", 20, true);
        for index in 0..5 {
            let mut recent = vote(&format!("recent-{index}"), "author", "reviewer", false);
            recent.created_at = 2;
            evidence.push(recent);
        }
        let forward = quality("target", "author", &evidence);
        evidence.reverse();
        assert_eq!(quality("target", "author", &evidence), forward);
        assert!(forward.author_reputation < 0.5);
    }

    #[test]
    fn direct_content_evidence_outweighs_author_prestige() {
        let mut respected = Vec::new();
        for index in 0..100 {
            respected.extend(history(&format!("reviewer-{index}"), 5, true));
        }
        let unrated_prestige = quality("target", "author", &respected);
        assert!(unrated_prestige.value <= 0.65);
        let useful_unknown = quality(
            "target",
            "unknown",
            &[vote("target", "unknown", "peer", true)],
        );
        assert!(useful_unknown.value > unrated_prestige.value);
        respected.push(vote("target", "author", "direct-reviewer", false));
        assert!(quality("target", "author", &respected).value < 0.5);
    }

    #[test]
    fn votes_for_other_authors_do_not_change_the_target_or_its_prior() {
        let original = quality(
            "target",
            "author",
            &[vote("target", "author", "peer", true)],
        );
        let mut evidence = vec![vote("target", "author", "peer", true)];
        evidence.push(vote("target", "unrelated", "peer", false));
        evidence.extend((0..100).map(|i| vote(&format!("record-{i}"), "unrelated", "peer", false)));
        assert_eq!(quality("target", "author", &evidence), original);
    }

    #[test]
    fn useful_supported_records_have_no_fixed_age_expiry() {
        let evidence: Vec<_> = (0..12)
            .map(|i| vote("target", "author", &format!("peer-{i}"), true))
            .collect();
        let useful = quality("target", "author", &evidence);
        let unrated = quality("unrated", "author", &[]);
        let thirty_days = 30 * 86_400;
        assert_eq!(retention_priority(&unrated, 0, thirty_days), 0.25);
        assert!(retention_priority(&unrated, 0, u64::MAX) < 0.000_001);
        assert!(retention_priority(&useful, 0, u64::MAX) > 0.69);
        assert_eq!(retention_priority(&unrated, 100, 0), unrated.value);
    }

    #[test]
    fn unicode_substrings_work_without_language_dictionaries() {
        assert_eq!(
            lexical_relevance("東京でAPI接続", "再試行", "", "東京 API"),
            1.0
        );
        assert_eq!(lexical_relevance("Straße Σ", "", "", "STRASSE ς"), 1.0);
        assert_eq!(lexical_relevance("CAFÉ", "", "", "café"), 1.0);
        assert_eq!(lexical_relevance("", "", "TLS", "tls"), 0.7);
        assert_eq!(lexical_relevance("tls", "", "", "TLS tls\tTLS"), 1.0);
        assert_eq!(lexical_relevance("anything", "", "", " \t\n"), 1.0);
        assert_eq!(lexical_relevance("anything", "", "", "missing"), 0.0);
    }

    #[test]
    fn search_preserves_relevance_and_uses_content_quality() {
        let useful = quality(
            "target",
            "author",
            &[vote("target", "author", "peer", true)],
        );
        let poor = quality(
            "target",
            "author",
            &[vote("target", "author", "peer", false)],
        );
        assert_eq!(search_score(0.0, &useful), 0.0);
        assert!(search_score(0.8, &useful) > search_score(0.8, &poor));
        assert!(search_score(1.0, &poor) > search_score(0.1, &useful));
        assert_eq!(search_score(f64::NAN, &useful), 0.0);
        assert!(search_score(2.0, &useful) <= 1.0);
    }
}
