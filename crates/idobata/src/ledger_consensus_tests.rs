use super::*;

struct App;
impl Application for App {
    fn validate(&self, block: &Block) -> Result<()> {
        if !block.transactions.is_empty() || block.next_application_hash == util::hash(b"invalid") {
            return Err(INVALID);
        }
        Ok(())
    }
}
struct Fixture {
    temp: tempfile::TempDir,
    keys: Vec<identity::Keypair>,
    authority: identity::Keypair,
    genesis: Signed<Genesis>,
}
impl Fixture {
    fn new(f: usize, one_operator: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let authority = identity::Keypair::generate_ed25519();
        let keys = (0..3 * f + 1)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(i, k)| Validator {
                peer_id: k.public().to_peer_id().to_string(),
                public_key: crypto::public(k),
                operator: if one_operator {
                    "actual-single-operator".into()
                } else {
                    format!("operator-{i}")
                },
            })
            .collect();
        let genesis = sign_genesis(
            &authority,
            Genesis {
                version: 1,
                chain_id: util::hash(b"closed test chain"),
                application_genesis_hash: util::hash(b"application genesis"),
                initial_application_hash: util::hash(b"initial state"),
                validators,
                fault_bound: f,
                quorum: 2 * f + 1,
                timeout_ms: 100,
                experiment_only: true,
            },
        )
        .unwrap();
        for i in 0..keys.len() {
            let home = temp.path().join(i.to_string());
            util::private_dir(&home).unwrap();
            util::atomic_write(&home.join("storage.key"), &[42; 32]).unwrap();
        }
        Self {
            temp,
            keys,
            authority,
            genesis,
        }
    }
    fn node(&self, i: usize) -> Node {
        Node::open(
            &self.temp.path().join(i.to_string()),
            self.keys[i].clone(),
            self.genesis.clone(),
            &self.authority.public().to_peer_id().to_string(),
        )
        .unwrap()
    }
    fn nodes(&self) -> Vec<Node> {
        (0..self.keys.len()).map(|i| self.node(i)).collect()
    }
    fn vote(&self, node: &Node, i: usize, round: u64, phase: Phase, id: Option<String>) -> Vote {
        let signed = VoteBody {
            genesis_hash: node.genesis_hash.clone(),
            height: node.height(),
            round,
            phase,
            validator: self.keys[i].public().to_peer_id().to_string(),
            block_id: id,
        };
        Signed {
            signature: crypto::sign(&self.keys[i], VOTE_DOMAIN, &signed).unwrap(),
            public_key: crypto::public(&self.keys[i]),
            signed,
        }
    }
}
fn proposal(nodes: &mut [Node], tag: &str) -> Proposal {
    let i = nodes
        .iter()
        .position(|n| n.own == n.proposer(n.round()))
        .unwrap();
    nodes[i]
        .propose(vec![], util::hash(tag.as_bytes()), &App)
        .unwrap()
}
fn prevotes(nodes: &mut [Node], p: &Proposal) -> Vec<Vote> {
    nodes
        .iter_mut()
        .map(|n| n.prevote(p, &App).unwrap())
        .collect()
}
fn deliver(nodes: &mut [Node], votes: &[Vote]) {
    for n in nodes {
        for v in votes {
            if n.height() == v.signed.height {
                let _ = n.observe_vote(v.clone()).unwrap();
            }
        }
    }
}
fn advance(nodes: &mut [Node]) {
    let votes = nodes
        .iter_mut()
        .map(|n| {
            n.round_started = Instant::now() - n.timeout_duration();
            n.timeout().unwrap()
        })
        .collect::<Vec<_>>();
    for n in nodes {
        let r = n.round();
        for t in &votes {
            if n.round() == r {
                n.observe_timeout(t.clone()).unwrap();
            }
        }
        assert_eq!(n.round(), r + 1);
    }
}
fn commit_round(nodes: &mut [Node], tag: &str) -> CommitCertificate {
    let p = proposal(nodes, tag);
    let votes = prevotes(nodes, &p);
    deliver(nodes, &votes);
    let commits = nodes
        .iter_mut()
        .map(|n| n.precommit().unwrap())
        .collect::<Vec<_>>();
    deliver(nodes, &commits);
    nodes[0].commits().last().unwrap().clone()
}

#[test]
fn two_phases_commit_restart_and_sequential_certified_sync() {
    let f = Fixture::new(1, false);
    let mut nodes = f.nodes();
    let c = commit_round(&mut nodes[..3], "block-one");
    assert!(nodes[..3].iter().all(|n| n.height() == 2));
    assert_eq!(nodes[3].height(), 1);
    nodes[3].import_commit(c.clone(), &App).unwrap();
    assert_eq!(
        nodes[3].commits()[0].block.id().unwrap(),
        c.block.id().unwrap()
    );
    let c2 = commit_round(&mut nodes, "block-two");
    assert_eq!(c2.block.parent, c.block.id().unwrap());
    assert!(nodes[3].import_commit(c, &App).is_err());
    let page = nodes[0].sync_page(0, usize::MAX);
    assert_eq!(page.len(), 2);
    drop(nodes);
    let reopened = f.node(0);
    assert_eq!(reopened.height(), 3);
    assert_eq!(reopened.sync_page(1, 8).len(), 1);
}

#[test]
fn two_two_partition_cannot_commit_or_advance_round() {
    let f = Fixture::new(1, false);
    let mut nodes = f.nodes();
    let p = proposal(&mut nodes, "partition");
    let votes = prevotes(&mut nodes, &p);
    deliver(&mut nodes[..2], &votes[..2]);
    deliver(&mut nodes[2..], &votes[2..]);
    assert!(nodes.iter_mut().all(|n| n.precommit().is_err()));
    let timeouts = nodes
        .iter_mut()
        .map(|n| {
            n.round_started = Instant::now() - n.timeout_duration();
            n.timeout().unwrap()
        })
        .collect::<Vec<_>>();
    for (i, n) in nodes.iter_mut().enumerate() {
        for t in &timeouts[(i / 2) * 2..(i / 2) * 2 + 2] {
            assert!(!n.observe_timeout(t.clone()).unwrap());
        }
        assert_eq!(n.height(), 1);
        assert_eq!(n.round(), 0);
    }
}

#[test]
fn seven_independent_operators_need_five_votes_for_f_two() {
    let f = Fixture::new(2, false);
    let mut nodes = f.nodes();
    let p = proposal(&mut nodes, "f-two");
    let votes = prevotes(&mut nodes, &p);
    deliver(&mut nodes, &votes[..4]);
    assert!(nodes[..4].iter_mut().all(|n| n.precommit().is_err()));
    deliver(&mut nodes, &votes[4..5]);
    let commits = nodes
        .iter_mut()
        .map(|n| n.precommit().unwrap())
        .collect::<Vec<_>>();
    deliver(&mut nodes, &commits[..4]);
    assert!(nodes[..4].iter().all(|n| n.height() == 1));
    deliver(&mut nodes, &commits[4..5]);
    assert!(nodes.iter().all(|n| n.height() == 2));
}

#[test]
fn real_four_hosts_one_operator_hold_without_signatures_or_minting() {
    let f = Fixture::new(1, true);
    let mut n = f.node(0);
    assert!(!n.ready());
    assert_eq!(n.independent_operators(), 1);
    assert!(n.propose(vec![], util::hash(b"reward"), &App).is_err());
    n.round_started = Instant::now() - Duration::from_secs(60);
    assert!(n.timeout().is_err());
    assert!(n.state.votes.is_empty());
    assert!(n.commits().is_empty());
}

#[test]
fn lock_survives_timeout_and_restart_and_higher_valid_round_unlocks() {
    let f = Fixture::new(1, false);
    let mut nodes = f.nodes();
    let p0 = proposal(&mut nodes, "locked-A");
    let pv0 = prevotes(&mut nodes, &p0);
    for v in &pv0[..3] {
        nodes[0].observe_vote(v.clone()).unwrap();
    }
    nodes[0].precommit().unwrap();
    assert_eq!(nodes[0].state.lock.as_ref().unwrap().round, 0);
    advance(&mut nodes);
    let mut n0 = nodes.remove(0);
    drop(n0);
    n0 = f.node(0);
    nodes.insert(0, n0);
    let p1 = proposal(&mut nodes, "new-B");
    assert_ne!(p0.signed.block.id().unwrap(), p1.signed.block.id().unwrap());
    assert!(
        nodes[0]
            .prevote(&p1, &App)
            .unwrap()
            .signed
            .block_id
            .is_none()
    );
    let mut pv1 = vec![];
    for n in &mut nodes[1..] {
        pv1.push(n.prevote(&p1, &App).unwrap());
    }
    deliver(&mut nodes, &pv1);
    advance(&mut nodes);
    let p2 = proposal(&mut nodes, "ignored-fresh-C");
    assert_eq!(p2.signed.valid_round, Some(1));
    assert_eq!(p2.signed.block.id().unwrap(), p1.signed.block.id().unwrap());
    assert_eq!(
        nodes[0].prevote(&p2, &App).unwrap().signed.block_id,
        Some(p1.signed.block.id().unwrap())
    );
}

#[test]
fn stale_pol_cannot_unlock_a_newer_lock() {
    let f = Fixture::new(1, false);
    let mut nodes = f.nodes();
    let a = proposal(&mut nodes, "A");
    let pva = prevotes(&mut nodes, &a);
    for v in &pva[..3] {
        nodes[0].observe_vote(v.clone()).unwrap();
    }
    nodes[0].precommit().unwrap();
    advance(&mut nodes);
    let b = proposal(&mut nodes, "B");
    nodes[0].prevote(&b, &App).unwrap();
    let pvb = nodes[1..]
        .iter_mut()
        .map(|n| n.prevote(&b, &App).unwrap())
        .collect::<Vec<_>>();
    deliver(&mut nodes, &pvb);
    nodes[0].precommit().unwrap();
    advance(&mut nodes);
    let body = ProposalBody {
        genesis_hash: nodes[0].genesis_hash.clone(),
        round: 2,
        proposer: f.keys[2].public().to_peer_id().to_string(),
        block: a.signed.block,
        valid_round: Some(0),
        valid_votes: pva[..3].to_vec(),
    };
    let stale = Signed {
        signature: crypto::sign(&f.keys[2], PROPOSAL_DOMAIN, &body).unwrap(),
        public_key: crypto::public(&f.keys[2]),
        signed: body,
    };
    assert!(
        nodes[0]
            .prevote(&stale, &App)
            .unwrap()
            .signed
            .block_id
            .is_none()
    );
}

#[test]
fn double_votes_have_durable_verifiable_evidence_and_replays_add_nothing() {
    let f = Fixture::new(1, false);
    let mut n = f.node(0);
    let a = f.vote(&n, 1, 0, Phase::Prevote, Some(util::hash(b"A")));
    let b = f.vote(&n, 1, 0, Phase::Prevote, Some(util::hash(b"B")));
    n.observe_vote(a.clone()).unwrap();
    n.observe_vote(a.clone()).unwrap();
    assert_eq!(n.state.votes.len(), 1);
    assert!(n.observe_vote(b.clone()).is_err());
    assert_eq!(n.evidence().len(), 1);
    n.verify_evidence(&n.evidence()[0]).unwrap();
    let mut fake = b;
    fake.signature = a.signature.clone();
    assert!(
        n.verify_evidence(&DoubleVoteEvidence {
            first: a,
            second: fake
        })
        .is_err()
    );
    drop(n);
    let n = f.node(0);
    assert_eq!(n.evidence().len(), 1);
}

#[test]
fn restart_refuses_double_sign_and_process_lock_prevents_duplicate_signers() {
    let f = Fixture::new(1, false);
    let mut nodes = f.nodes();
    let p = proposal(&mut nodes, "A");
    let signed = nodes[0].prevote(&p, &App).unwrap();
    assert!(
        Node::open(
            &f.temp.path().join("0"),
            f.keys[0].clone(),
            f.genesis.clone(),
            &f.authority.public().to_peer_id().to_string()
        )
        .is_err()
    );
    let n = nodes.remove(0);
    drop(n);
    let mut n = f.node(0);
    assert_eq!(n.prevote(&p, &App).unwrap().signature, signed.signature);
    let mut conflicting = p;
    conflicting.signed.block.next_application_hash = util::hash(b"B");
    conflicting.signature = crypto::sign(&f.keys[0], PROPOSAL_DOMAIN, &conflicting.signed).unwrap();
    assert!(n.prevote(&conflicting, &App).is_err());
}

#[test]
fn disk_failure_releases_no_signature_and_keeps_previous_signer_state() {
    let f = Fixture::new(1, false);
    let mut nodes = f.nodes();
    let p = proposal(&mut nodes, "A");
    let old = nodes[1].path.clone();
    nodes[1].path = f.temp.path().join("missing-parent").join("cannot-save.enc");
    assert!(nodes[1].prevote(&p, &App).is_err());
    assert!(nodes[1].state.votes.is_empty());
    nodes[1].path = old;
    assert!(nodes[1].prevote(&p, &App).is_ok());
}

#[test]
fn invalid_application_and_genesis_replay_fail_closed() {
    let f = Fixture::new(1, false);
    let mut n = f.node(0);
    assert!(n.propose(vec![], util::hash(b"invalid"), &App).is_err());
    assert!(n.state.proposals.is_empty());
    let mut g = f.genesis.clone();
    g.signed.chain_id = util::hash(b"other-chain");
    drop(n);
    assert!(
        Node::open(
            &f.temp.path().join("0"),
            f.keys[0].clone(),
            g,
            &f.authority.public().to_peer_id().to_string()
        )
        .is_err()
    );
    let path = f.temp.path().join("0/ledger-consensus.enc");
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    util::atomic_write(&path, &bytes).unwrap();
    assert!(
        Node::open(
            &f.temp.path().join("0"),
            f.keys[0].clone(),
            f.genesis.clone(),
            &f.authority.public().to_peer_id().to_string()
        )
        .is_err()
    );
}

#[test]
fn uncertified_commit_and_duplicate_validator_quorum_are_rejected() {
    let f = Fixture::new(1, false);
    let mut nodes = f.nodes();
    let p = proposal(&mut nodes, "A");
    let id = Some(p.signed.block.id().unwrap());
    let vote = f.vote(&nodes[0], 1, 0, Phase::Precommit, id);
    let cert = CommitCertificate {
        genesis_hash: nodes[0].genesis_hash.clone(),
        round: 0,
        block: p.signed.block,
        precommits: vec![vote.clone(), vote.clone(), vote],
    };
    assert!(nodes[0].import_commit(cert, &App).is_err());
    assert_eq!(nodes[0].height(), 1);
}

fn certified_next(f: &Fixture, node: &Node) -> CommitCertificate {
    let (parent, previous_application_hash) = node.previous().unwrap();
    let block = Block {
        height: node.height(),
        parent,
        previous_application_hash,
        next_application_hash: util::hash(node.height().to_be_bytes().as_slice()),
        transactions: vec![],
    };
    let id = Some(block.id().unwrap());
    let precommits = (0..f.genesis.signed.quorum)
        .map(|i| f.vote(node, i, 0, Phase::Precommit, id.clone()))
        .collect();
    CommitCertificate {
        genesis_hash: node.genesis_hash.clone(),
        round: 0,
        block,
        precommits,
    }
}

#[test]
fn authenticated_compaction_retains_tail_and_active_signing_lock() {
    let f = Fixture::new(1, false);
    let mut n = f.node(0);
    for _ in 0..66 {
        let c = certified_next(&f, &n);
        n.import_commit(c, &App).unwrap();
    }
    let (parent, previous_application_hash) = n.previous().unwrap();
    let block = Block {
        height: n.height(),
        parent,
        previous_application_hash,
        next_application_hash: util::hash(b"locked after checkpoint"),
        transactions: vec![],
    };
    let proposer_index = (n.height() as usize - 1) % f.keys.len();
    let body = ProposalBody {
        genesis_hash: n.genesis_hash.clone(),
        round: 0,
        proposer: f.keys[proposer_index].public().to_peer_id().to_string(),
        block,
        valid_round: None,
        valid_votes: vec![],
    };
    let p = Signed {
        signature: crypto::sign(&f.keys[proposer_index], PROPOSAL_DOMAIN, &body).unwrap(),
        public_key: crypto::public(&f.keys[proposer_index]),
        signed: body,
    };
    n.prevote(&p, &App).unwrap();
    for i in 0..3 {
        let v = f.vote(&n, i, 0, Phase::Prevote, Some(p.signed.block.id().unwrap()));
        n.observe_vote(v).unwrap();
    }
    let signed = n.precommit().unwrap();
    let head = n.commits().last().unwrap().clone();
    assert!(
        n.compact_at_head(head.block.height, &util::hash(b"wrong root"))
            .is_err()
    );
    n.compact_at_head(head.block.height, &head.block.next_application_hash)
        .unwrap();
    assert_eq!(n.commits().len(), SYNC_TAIL_BLOCKS);
    assert_eq!(n.checkpoint().unwrap().block.height, 66);
    drop(n);
    let mut n = f.node(0);
    assert_eq!(n.height(), 67);
    assert!(n.state.lock.is_some());
    assert_eq!(n.precommit().unwrap().signature, signed.signature);
    assert_eq!(n.sync_page(0, usize::MAX).len(), 8);
}

#[test]
fn minimum_anchor_rejects_old_journal_and_compaction_crash_recovers() {
    let f = Fixture::new(1, false);
    let mut n = f.node(0);
    let old = std::fs::read(&n.path).unwrap();
    let c = certified_next(&f, &n);
    n.import_commit(c.clone(), &App).unwrap();
    let real_path = n.path.clone();
    let directory = f.temp.path().join("0/not-a-file");
    std::fs::create_dir(&directory).unwrap();
    n.path = directory;
    assert!(
        n.compact_at_head(c.block.height, &c.block.next_application_hash)
            .is_err()
    );
    assert!(n.storage_blocked);
    drop(n);
    let n = f.node(0);
    assert_eq!(n.height(), 2);
    drop(n);
    let valid = std::fs::read(&real_path).unwrap();
    util::atomic_write(&real_path, &old).unwrap();
    assert!(
        Node::open(
            &f.temp.path().join("0"),
            f.keys[0].clone(),
            f.genesis.clone(),
            &f.authority.public().to_peer_id().to_string()
        )
        .is_err()
    );
    util::atomic_write(&real_path, &valid).unwrap();
    assert_eq!(f.node(0).height(), 2);
}

#[test]
fn fresh_checkpoint_import_resumes_after_anchor_crash_but_cannot_reset_signed_wal() {
    let f = Fixture::new(1, false);
    let source = f.node(0);
    let cert = certified_next(&f, &source);
    drop(source);
    let mut n = f.node(3);
    let bad = f.temp.path().join("3/not-a-file");
    std::fs::create_dir(&bad).unwrap();
    n.path = bad;
    assert!(
        n.import_checkpoint(
            cert.clone(),
            cert.block.height,
            &cert.block.next_application_hash
        )
        .is_err()
    );
    drop(n);
    assert!(
        Node::open(
            &f.temp.path().join("3"),
            f.keys[3].clone(),
            f.genesis.clone(),
            &f.authority.public().to_peer_id().to_string()
        )
        .is_err()
    );
    let mut recovered = Node::open_from_checkpoint(
        &f.temp.path().join("3"),
        f.keys[3].clone(),
        f.genesis.clone(),
        &f.authority.public().to_peer_id().to_string(),
        cert.clone(),
        cert.block.height,
        &cert.block.next_application_hash,
    )
    .unwrap();
    assert_eq!(recovered.height(), 2);
    assert!(
        recovered
            .import_checkpoint(
                cert.clone(),
                cert.block.height,
                &cert.block.next_application_hash
            )
            .is_err()
    );
    let mut nodes = vec![f.node(0), f.node(1), f.node(2)];
    let p = proposal(&mut nodes, "cannot reset signed node");
    nodes[1].prevote(&p, &App).unwrap();
    for i in 0..3 {
        let vote = f.vote(
            &nodes[1],
            i,
            0,
            Phase::Prevote,
            Some(p.signed.block.id().unwrap()),
        );
        nodes[1].observe_vote(vote).unwrap();
    }
    nodes[1].precommit().unwrap();
    assert!(
        nodes[1]
            .import_checkpoint(
                cert.clone(),
                cert.block.height,
                &cert.block.next_application_hash
            )
            .is_err()
    );
}

#[test]
fn two_equivocating_validators_cannot_unlock_three_honest_locks_in_f_two() {
    let f = Fixture::new(2, false);
    let mut nodes = f.nodes();
    let a = proposal(&mut nodes, "A");
    let votes = prevotes(&mut nodes, &a);
    for n in &mut nodes[2..5] {
        for v in &votes[..5] {
            n.observe_vote(v.clone()).unwrap();
        }
        n.precommit().unwrap();
    }
    advance(&mut nodes);
    // The new leader is Byzantine and ignores its validValue. The two Byzantine
    // identities equivocate; three honest validators must keep their old locks.
    let (parent, previous_application_hash) = nodes[1].previous().unwrap();
    let block = Block {
        height: 1,
        parent,
        previous_application_hash,
        next_application_hash: util::hash(b"B"),
        transactions: vec![],
    };
    let body = ProposalBody {
        genesis_hash: nodes[1].genesis_hash.clone(),
        round: 1,
        proposer: f.keys[1].public().to_peer_id().to_string(),
        block,
        valid_round: None,
        valid_votes: vec![],
    };
    let p = Signed {
        signature: crypto::sign(&f.keys[1], PROPOSAL_DOMAIN, &body).unwrap(),
        public_key: crypto::public(&f.keys[1]),
        signed: body,
    };
    let mut b_votes = vec![
        f.vote(
            &nodes[0],
            0,
            1,
            Phase::Prevote,
            Some(p.signed.block.id().unwrap()),
        ),
        f.vote(
            &nodes[0],
            1,
            1,
            Phase::Prevote,
            Some(p.signed.block.id().unwrap()),
        ),
    ];
    for n in &mut nodes[2..] {
        let vote = n.prevote(&p, &App).unwrap();
        if vote.signed.block_id.is_some() {
            b_votes.push(vote)
        }
    }
    assert_eq!(b_votes.len(), 4);
    deliver(&mut nodes[2..], &b_votes);
    for n in &mut nodes[2..5] {
        assert!(n.precommit().is_err());
        assert_eq!(
            n.state.lock.as_ref().unwrap().block.id().unwrap(),
            a.signed.block.id().unwrap()
        );
    }
}

#[test]
fn application_reconciliation_replays_only_verified_prefix_and_rejects_ahead() {
    let f = Fixture::new(1, false);
    let mut n = f.node(0);
    assert!(
        n.reconcile_application(0, None, &f.genesis.signed.initial_application_hash)
            .unwrap()
    );
    let c = certified_next(&f, &n);
    n.import_commit(c.clone(), &App).unwrap();
    assert!(
        !n.reconcile_application(0, None, &f.genesis.signed.initial_application_hash)
            .unwrap()
    );
    assert!(
        n.reconcile_application(
            1,
            Some(&c.block.id().unwrap()),
            &c.block.next_application_hash
        )
        .unwrap()
    );
    assert!(
        n.reconcile_application(2, None, &c.block.next_application_hash)
            .is_err()
    );
    assert!(
        n.reconcile_application(
            1,
            Some(&util::hash(b"fork")),
            &c.block.next_application_hash
        )
        .is_err()
    );
    assert!(
        n.reconcile_application(1, Some(&c.block.id().unwrap()), &util::hash(b"bad root"))
            .is_err()
    );
}

fn timeout_qc(f: &Fixture, n: &Node, round: u64, signers: &[usize]) -> TimeoutCertificate {
    let timeouts = signers
        .iter()
        .map(|i| {
            let signed = TimeoutBody {
                genesis_hash: n.genesis_hash.clone(),
                height: n.height(),
                round,
                validator: f.keys[*i].public().to_peer_id().to_string(),
            };
            Signed {
                signature: crypto::sign(&f.keys[*i], TIMEOUT_DOMAIN, &signed).unwrap(),
                public_key: crypto::public(&f.keys[*i]),
                signed,
            }
        })
        .collect();
    TimeoutCertificate {
        genesis_hash: n.genesis_hash.clone(),
        height: n.height(),
        round,
        timeouts,
    }
}

#[test]
fn more_than_256_timeouts_gc_history_keep_locks_and_reconnect_with_quorum_proof() {
    let f = Fixture::new(1, false);
    let mut n = f.node(0);
    let p = n
        .propose(vec![], util::hash(b"long lived lock"), &App)
        .unwrap();
    n.prevote(&p, &App).unwrap();
    for i in 0..3 {
        let v = f.vote(&n, i, 0, Phase::Prevote, Some(p.signed.block.id().unwrap()));
        n.observe_vote(v).unwrap();
    }
    n.precommit().unwrap();
    for round in 0..272 {
        let qc = timeout_qc(&f, &n, round, &[0, 1, 2]);
        assert!(n.observe_timeout_certificate(qc).unwrap());
        assert!(n.state.votes.len() <= 4 * f.keys.len());
        assert!(n.state.timeouts.len() <= 2 * f.keys.len());
    }
    assert_eq!(n.round(), 272);
    assert!(n.state.lock.is_some());
    let qc = n.round_certificate().unwrap().clone();
    drop(n);
    let mut nodes = f.nodes();
    assert_eq!(nodes[0].round(), 272);
    assert!(nodes[0].state.lock.is_some());
    for node in &mut nodes[1..] {
        assert!(node.observe_timeout_certificate(qc.clone()).unwrap());
        assert_eq!(node.round(), 272);
    }
    let c = commit_round(&mut nodes, "new input ignored in favor of validValue");
    assert_eq!(c.block.id().unwrap(), p.signed.block.id().unwrap());
    assert!(nodes.iter().all(|n| n.height() == 2));
}

#[test]
fn two_byzantine_future_timeout_signatures_cannot_jump_f_two_round() {
    let f = Fixture::new(2, false);
    let mut n = f.node(0);
    let forged_quorum = timeout_qc(&f, &n, 10_000, &[0, 1]);
    assert!(
        n.observe_timeout_certificate(forged_quorum.clone())
            .is_err()
    );
    assert_eq!(n.round(), 0);
    for timeout in forged_quorum.timeouts {
        assert!(n.observe_timeout(timeout).is_err());
    }
    assert_eq!(n.round(), 0);
    let valid = timeout_qc(&f, &n, 10_000, &[0, 1, 2, 3, 4]);
    assert!(n.observe_timeout_certificate(valid).unwrap());
    assert_eq!(n.round(), 10_001);
    assert!(n.proposer(u64::MAX).len() > 10);
    let invalid = timeout_qc(&f, &n, MAX_ROUNDS, &[0, 1, 2, 3, 4]);
    assert!(n.observe_timeout_certificate(invalid).is_err());
}

#[test]
fn double_vote_evidence_is_one_proof_per_validator_across_heights() {
    let f = Fixture::new(1, false);
    let mut n = f.node(0);
    for _ in 0..5 {
        let first = f.vote(&n, 1, 0, Phase::Prevote, Some(util::hash(b"a")));
        let second = f.vote(&n, 1, 0, Phase::Prevote, Some(util::hash(b"b")));
        n.observe_evidence(DoubleVoteEvidence { first, second })
            .unwrap();
        let cert = certified_next(&f, &n);
        n.import_commit(cert, &App).unwrap();
    }
    assert_eq!(n.evidence().len(), 1);
    drop(n);
    assert_eq!(f.node(0).evidence().len(), 1);
}

#[test]
fn higher_certified_checkpoint_advances_signed_height_and_preserves_evidence() {
    let f = Fixture::new(1, false);
    let mut target = f.node(0);
    let mut source = f.node(1);
    let first = certified_next(&f, &target);
    let body = ProposalBody {
        genesis_hash: target.genesis_hash.clone(),
        round: 0,
        proposer: f.keys[0].public().to_peer_id().to_string(),
        block: first.block.clone(),
        valid_round: None,
        valid_votes: vec![],
    };
    let p = Signed {
        signature: crypto::sign(&f.keys[0], PROPOSAL_DOMAIN, &body).unwrap(),
        public_key: crypto::public(&f.keys[0]),
        signed: body,
    };
    target.prevote(&p, &App).unwrap();
    for i in 0..3 {
        let v = f.vote(
            &target,
            i,
            0,
            Phase::Prevote,
            Some(p.signed.block.id().unwrap()),
        );
        target.observe_vote(v).unwrap();
    }
    target.precommit().unwrap();
    let first_bad = f.vote(&target, 3, 0, Phase::Prevote, Some(util::hash(b"first")));
    let second_bad = f.vote(&target, 3, 0, Phase::Prevote, Some(util::hash(b"second")));
    target
        .observe_evidence(DoubleVoteEvidence {
            first: first_bad,
            second: second_bad,
        })
        .unwrap();
    source.import_commit(first, &App).unwrap();
    let higher = certified_next(&f, &source);
    source.import_commit(higher.clone(), &App).unwrap();
    target
        .import_checkpoint(
            higher.clone(),
            higher.block.height,
            &higher.block.next_application_hash,
        )
        .unwrap();
    assert_eq!(target.height(), 3);
    assert_eq!(target.evidence().len(), 1);
    assert!(target.local_votes().is_empty());
    assert!(target.state.lock.is_none());
    assert!(
        target
            .import_checkpoint(
                higher.clone(),
                higher.block.height,
                &higher.block.next_application_hash
            )
            .is_err()
    );
    drop(target);
    let target = f.node(0);
    assert_eq!(target.height(), 3);
    assert_eq!(target.evidence().len(), 1);
}
