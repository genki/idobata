#!/usr/bin/env python3
"""Opt-in SDK 0.4 ledger acceptance on seven temporary nodes across four hosts.

The existing four-host inventory supplies candidate native executables and
temporary roots. Seven locally generated fixture identities are distributed
2+2+2+1. Their seven operator registrations are synthetic: all four real hosts
belong to one actual operator. This proves transport/application behavior, not
independent production validators. No production service or home is changed.

Only public signed settings and certificates travel between hosts. Node identity
and storage keys stay in the generated temporary home on their own host. Agent
operations use the production CLI over each daemon's ordinary IPC endpoint.
The evidence excludes bodies, identifiers, addresses and private failure text.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time


SPEC = importlib.util.spec_from_file_location(
    'idobata_knowledge_fixture', Path(__file__).with_name('verify-knowledge-peers.py'))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
HELPERS = FIXTURE.HELPERS
check = FIXTURE.check
Failure = FIXTURE.VerificationFailure
ROOM = 'ledger-experiment'
PLACEMENT = (0, 1, 2, 3, 0, 1, 2)
PORTS = tuple(range(39230, 39237))
WAIT_SECONDS = 90
PARAMETERS = {
    'blocks_per_epoch': 100, 'epoch_mint_cap': 32, 'minimum_system_reward': 1,
    'question_fee': 0, 'attempts_per_operator_epoch': 8,
    'active_questions_per_operator': 4, 'minimum_deadline_blocks': 5,
    'maximum_deadline_blocks': 50, 'maximum_active_questions': 128,
    'operator_state_bytes': 256 * 1024, 'answers_per_question': 8,
    'answers_per_operator_question': 2, 'maximum_batch_transactions': 64,
}


def parallel(function, values):
    with ThreadPoolExecutor(max_workers=7) as executor:
        return list(executor.map(function, values))


def expand_inventory(inventory):
    check(isinstance(inventory, list) and len(inventory) == 4, 'expected_four_hosts')
    check(sum(not row.get('ssh') for row in inventory) == 1,
          'expected_one_local_coordinator')
    # Anchor all administrative signing on the coordinator's temporary identity.
    physical = sorted(inventory, key=lambda row: bool(row.get('ssh')))
    check(physical[0].get('platform') == 'linux', 'local_coordinator_must_be_linux')
    aliases = [row.get('ssh') for row in physical[1:]]
    check(len(set(aliases)) == 3, 'duplicate_physical_host_alias')
    check(set(row.get('platform') for row in physical) == {'linux', 'macos', 'windows'},
          'expected_three_native_platforms')
    configurations = []
    for index, host in enumerate(PLACEMENT):
        selected = FIXTURE.fixture_node_config(physical[host], index, PORTS[index])
        check(selected.get('binary_sha256') is not None, 'native_binary_hash_required')
        selected['physical_host'] = host
        configurations.append(selected)
    return configurations


def forward_plan(placement=PLACEMENT, ports=PORTS):
    """One SSH process per physical host avoids duplicate reverse listeners."""
    return {
        host: {
            'local': [port for owner, port in zip(placement, ports) if owner == host],
            'reverse': [port for owner, port in zip(placement, ports) if owner != host],
        }
        for host in sorted(set(placement)) if host != 0
    }


class LedgerNode(FIXTURE.FixtureNode):
    def argv(self, args):
        # Ordinary agent calls receive only the IPC locator, never a key path.
        administrative = args[:2] in [
            ['ledger', 'genesis'], ['ledger', 'configure'], ['ledger', 'export']]
        ordinary = args and args[0] in ['info', 'ledger', 'knowledge']
        if ordinary and not administrative and hasattr(self, 'agent_endpoint'):
            command = [self.binary, '--socket', self.agent_endpoint, '--json'] + args
            if not self.host:
                return command
            rendered = subprocess.list2cmdline(command) if self.win else shlex.join(command)
            return HELPERS.SSH + [self.host, rendered]
        return super().argv(args)


def question_id(chain, source):
    encoded = json.dumps(['idobata.ledger.question.v1', [chain, source]],
                         separators=(',', ':'), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def safe_status(value):
    """Diagnostics are fixed numeric projections, never raw ledger status."""
    fields = ['application_height', 'total_minted', 'pending_transactions',
              'queued_requests', 'pending_requests', 'seconds_since_commit']
    result = {key: value[key] for key in fields if type(value.get(key)) is int}
    state = value.get('status')
    result['state'] = state if state in ['ready', 'hold', 'fault'] else 'invalid'
    consensus = value.get('consensus', {})
    if isinstance(consensus, dict):
        result['consensus'] = {key: consensus[key] for key in [
            'height', 'round', 'prevotes', 'precommits', 'double_vote_evidence']
            if type(consensus.get(key)) is int}
    return result


def pending(value):
    # A transport failure has unknown outcome and must never trigger fresh-nonce
    # retry. Preserve it as a failed fixture with private IPC diagnostics.
    check(value.get('status') == 'pending' and value.get('finalized') is False,
          'mutation_not_durably_pending')
    identifier = value.get('transaction_id')
    check(isinstance(identifier, str) and FIXTURE.ID_PATTERN.fullmatch(identifier),
          'pending_transaction_id_missing')
    return identifier


def self_test():
    base = [
        {'platform': 'linux', 'root': '/tmp/idobata-ledger-fixture', 'binary': '/tmp/sdk'},
        {'platform': 'macos', 'ssh': 'mac-one', 'root': '/tmp/idobata-ledger-fixture',
         'binary': '/tmp/sdk'},
        {'platform': 'macos', 'ssh': 'mac-two', 'root': '/tmp/idobata-ledger-fixture',
         'binary': '/tmp/sdk'},
        {'platform': 'windows', 'ssh': 'windows',
         'root': 'C:/Users/fixture/AppData/Local/Temp/idobata-ledger-fixture',
         'binary': 'C:/Users/fixture/AppData/Local/Temp/sdk.exe'},
    ]
    for row in base:
        row.update(binary_sha256='a' * 64, home='production-sentinel',
                   identity='private-sentinel', endpoint='production-endpoint')
    configurations = expand_inventory(base)
    check(len(configurations) == 7 and len({row['port'] for row in configurations}) == 7,
          'expanded_nodes_or_ports_not_distinct')
    check(all(not set(row) & {'home', 'identity', 'endpoint'} for row in configurations),
          'production_metadata_propagated')
    plan = forward_plan()
    for host, forwards in plan.items():
        check(set(forwards['local']).isdisjoint(forwards['reverse'])
              and len(forwards['local']) + len(forwards['reverse']) == 7,
              'duplicate_or_missing_forward')
        check(len(forwards['reverse']) == len(set(forwards['reverse'])),
              'duplicate_reverse_listener')
    # Every node reaches every remote node either natively on its own host or
    # through exactly one forward. A remote port must not shadow a local daemon.
    for source, source_host in enumerate(PLACEMENT):
        for target, target_host in enumerate(PLACEMENT):
            if source == target or source_host == target_host:
                continue
            if source_host != 0:
                check(PORTS[target] in plan[source_host]['reverse'], 'missing_outbound_route')
            if target_host != 0:
                check(PORTS[target] in plan[target_host]['local'], 'missing_inbound_route')
    rejected = 0
    for change in ['missing_hash', 'production_root', 'duplicate_host']:
        changed = [dict(row) for row in base]
        if change == 'missing_hash':
            changed[0].pop('binary_sha256')
        elif change == 'production_root':
            changed[0]['root'] = '/var/lib/idobata'
        else:
            changed[2]['ssh'] = changed[1]['ssh']
        try:
            expand_inventory(changed)
        except Failure:
            rejected += 1
        else:
            raise Failure('unsafe_inventory_accepted')
    projected = safe_status({'status': 'ready', 'application_height': 3,
                             'peer_id': 'private-sentinel', 'balance': 42,
                             'reason': 'private-sentinel', 'pending': ['private-sentinel'],
                             'performance': {'private-sentinel': 1},
                             'consensus': {'height': 4, 'round': 2,
                                           'block_id': 'private-sentinel'}})
    check('private-sentinel' not in json.dumps(projected) and 'balance' not in projected,
          'private_status_diagnostic_leak')
    return {'expanded_temporary_nodes': 7, 'physical_hosts': 4,
            'directed_routes_checked': 42, 'rejected_unsafe_inventories': rejected,
            'body_free_diagnostic_projection': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory')
    parser.add_argument('--output')
    parser.add_argument('--source-sha256')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps({'status': 'passed', **self_test()}), flush=True)
        return 0
    if not args.inventory or not args.output or not args.source_sha256:
        parser.error('--inventory, --output and --source-sha256 are required')
    if not FIXTURE.ID_PATTERN.fullmatch(args.source_sha256):
        parser.error('--source-sha256 must be a lowercase SHA256')
    output = Path(args.output).resolve()
    if output.exists():
        parser.error('--output must be new; earlier attempts are preserved')
    output.parent.mkdir(parents=True, exist_ok=True)
    run_id = str(time.time_ns())
    logs = output.parent / ('private-ledger-logs-' + run_id)
    logs.mkdir(mode=0o700)
    report = {
        'version': 1, 'test': 'real-four-host-synthetic-seven-operator-ledger',
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'status': 'running', 'checks': {}, 'production_services_changed': False,
        'source_archive_sha256': args.source_sha256,
        'source_provenance': 'manager_build_evidence_label_not_cli_attestation',
        'physical_host_count': 4, 'native_platform_count': 3,
        'actual_operator_count': 1, 'synthetic_operator_count': 7,
        'independent_production_operators_proven': False,
        'genesis': {'experiment_only': True, 'fault_bound': 2, 'quorum': 5,
                    'timeout_ms': 3000, 'bootstrap_units': 0, 'question_bounty': 0},
    }
    nodes, tunnels = [], []
    verified = False
    stage = 'inventory'

    def record(label, value=True):
        report['checks'][label] = value
        FIXTURE.atomic_report(output, report)
        print(json.dumps({'check': label, 'result': value}), flush=True)

    def wait(label, condition, timeout=WAIT_SECONDS):
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if condition():
                record(label, {'passed': True,
                               'elapsed_seconds': round(time.monotonic() - started, 3)})
                return
            time.sleep(0.5)
        raise Failure('phase_deadline_exceeded', phase=label)

    def call(index, arguments, data=None, codes=(0,)):
        nodes[index].phase = stage
        encoded = json.dumps(data, ensure_ascii=False) if data is not None else None
        return nodes[index].run(arguments, encoded, codes=codes)

    def confirmed(index, transaction):
        return call(index, ['ledger', 'tx', '--id', transaction], codes=(0, 10)) \
            .get('status') == 'confirmed'

    try:
        record('fixture_guards', self_test())
        configurations = expand_inventory(json.loads(Path(args.inventory).read_text()))
        nodes = [LedgerNode(config, logs, run_id + '-' + str(index))
                 for index, config in enumerate(configurations)]
        stage = 'native_artifacts'
        artifacts = []
        for host in range(4):
            node = next(node for node in nodes if node.c['physical_host'] == host)
            actual = node.binary_sha256()
            check(actual == node.c['binary_sha256'], 'native_binary_hash_mismatch')
            artifacts.append({'physical_host_index': host,
                              'platform': node.c['platform'], 'sha256': actual})
            result = subprocess.run(node.argv(['--version']), capture_output=True, timeout=30)
            check(result.returncode == 0
                  and result.stdout.decode('utf-8-sig').strip() == 'idobata 0.4.0',
                  'sdk_04_candidate_required')
        verified = True
        record('verified_native_artifacts', artifacts)
        stage = 'initialize_private_homes'
        identities = []
        for node in nodes:
            node.initialized = True
            initialized = node.run(['init', '--listen',
                                    f'/ip4/127.0.0.1/tcp/{node.port}'])
            identities.append(initialized['identity'])
            node.agent_endpoint = initialized['endpoint']
        peers = [identity['peer_id'] for identity in identities]
        check(len(set(peers)) == 7, 'fixture_identities_not_distinct')
        profiles = parallel(lambda node: node.run(['profile']), nodes)
        check(all(profile == profiles[0] for profile in profiles), 'native_scanner_policy_differs')
        record('distinct_private_fixture_identities', len(peers))
        first = nodes[0]
        stage = 'authorize_synthetic_operators'
        first.put(first.home + '/members.json', json.dumps(identities))
        claims = {'bindings': {peer: 'synthetic-operator-' + str(i)
                               for i, peer in enumerate(peers)},
                  'credits': {'synthetic-operator-' + str(i): 1000 for i in range(7)}}
        first.put(first.home + '/operators.json', json.dumps(claims))
        created = first.run(['room', 'create', '--room', ROOM, '--members-file',
                             first.home + '/members.json', '--operators-file',
                             first.home + '/operators.json', '--output', first.home + '/invite.json'])
        authority = created['authority_peer_id']
        invite = Path(first.home + '/invite.json').read_bytes()
        certificate = json.loads(invite)
        check(certificate['signed']['knowledge_operators']['bindings'] == claims['bindings'],
              'synthetic_operator_bindings_changed')
        for node in nodes[1:]:
            node.put(node.home + '/invite.json', invite)
            node.run(['room', 'join', '--room', ROOM, '--invite-file',
                      node.home + '/invite.json', '--trust-authority', authority])
        stage = 'configure_protected_experimental_genesis'
        application = {
            'version': 1, 'experiment_only': True,
            'room_id': certificate['signed']['room_id'],
            'network_salt': hashlib.sha256(('isolated real-host ledger ' + run_id).encode()).hexdigest(),
            'authority_peer_id': authority, 'operator_epoch': 1,
            'participants': {row['peer_id']: {
                'public_key': row['public_key'], 'operator': claims['bindings'][row['peer_id']],
                'credit': 1000} for row in identities},
            'parameters': PARAMETERS, 'bootstrap_balances': {},
        }
        validators = [{'peer_id': row['peer_id'], 'public_key': row['public_key'],
                       'operator': claims['bindings'][row['peer_id']]} for row in identities]
        first.put(first.home + '/application-genesis.json', json.dumps(application))
        first.put(first.home + '/validators.json', json.dumps(validators))
        signed = first.run(['ledger', 'genesis', '--input', first.home + '/application-genesis.json',
                            '--validators-file', first.home + '/validators.json', '--room', ROOM,
                            '--fault-bound', '2', '--timeout-ms', '3000', '--output',
                            first.home + '/signed-settings.json'])
        check(signed.get('bootstrap_units') == 0 and signed.get('experiment_only') is True,
              'genesis_not_zero_bootstrap_experiment')
        chain = signed['chain_id']
        settings = Path(first.home + '/signed-settings.json').read_bytes()
        for node in nodes:
            node.put(node.home + '/settings-import.json', settings)
            node.run(['ledger', 'configure', '--settings-file', node.home + '/settings-import.json'])
        record('fixed_f2_seven_validator_zero_bootstrap_genesis')
        stage = 'loopback_only_transport'
        for host, plan in forward_plan().items():
            node = next(node for node in nodes if node.c['physical_host'] == host)
            command = HELPERS.SSH + ['-N', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                                     '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15']
            for port in plan['local']:
                command += ['-L', f'127.0.0.1:{port}:127.0.0.1:{port}']
            for port in plan['reverse']:
                command += ['-R', f'127.0.0.1:{port}:127.0.0.1:{port}']
            command.append(node.host)
            tunnels.append(subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                            stdout=node.log, stderr=node.log))
        time.sleep(1)
        check(all(tunnel.poll() is None for tunnel in tunnels), 'fixture_forward_failed')
        parallel(lambda node: node.start(), nodes)
        wait('authorized_full_mesh_seven_nodes', lambda: all(
            value.get('connected_peers') == 6 and value.get('ledger', {}).get('status') == 'ready'
            for value in parallel(lambda i: call(i, ['info']), range(7))))
        check(all(value.get('balance') == 0 for value in parallel(
            lambda i: call(i, ['ledger', 'balance']), range(7))), 'nonzero_initial_balance')
        stage = 'inspect_publish_and_replicate_references'
        selected = []
        published = 0
        for kind, author in [(0, 0), (1, 0), (2, 1)]:
            for attempt in range(12):
                body = {
                    'problem': f'Private synthetic ledger fixture case {kind} variant {attempt}.',
                    'solution': [
                        'Find the documented safe cache reset procedure.',
                        'Accept stopping the worker, clearing only its cache, restarting and verifying.',
                        'Stop the worker, clear only its cache, restart and verify the next result.',
                    ][kind],
                    'context': 'Isolated synthetic test data. No commands in this text are executed.',
                    'references': [], 'kind': 'answer' if kind == 2 else 'hint',
                }
                # Space writes rather than bypassing production resource limits.
                delay = nodes[author].last_mutation + 6.1 - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                nodes[author].last_mutation = time.monotonic()
                value = call(author, ['knowledge', 'publish', '--room', ROOM, '--stdin'], body)
                published += 1
                check(value.get('stored') is True and value.get('replication_factor') == 3,
                      'inspected_reference_not_accepted')
                keepers = value.get('assigned_keepers')
                check(isinstance(keepers, list) and len(keepers) == 3, 'keeper_assignment_missing')
                if peers[2] not in keepers:
                    selected.append({'id': value['id'], 'keepers': keepers})
                    break
            else:
                raise Failure('could_not_select_nonkeeper_finder')
        record('published_reference_candidates', published)

        def replicated():
            snapshots = parallel(lambda i: call(i, ['knowledge', 'status', '--room', ROOM]), range(7))
            for record in selected:
                holders = [(i, row) for i, state in enumerate(snapshots)
                           for row in state.get('records', []) if row.get('id') == record['id']]
                if len(holders) != 3 or any(
                        row.get('staging') is not False or peers[i] not in record['keepers']
                        or i == 2 for i, row in holders):
                    return False
            return True

        wait('three_keeper_copies_without_finder_copy', replicated)
        stage = 'question_admission_and_commit'
        # Start with a full same-epoch deadline window. This changes no consensus
        # timer; it avoids making a fresh request near application epoch expiry.
        wait('same_epoch_question_window', lambda:
             call(0, ['ledger', 'status'])['application_height'] % 100 < 40)
        height = call(0, ['ledger', 'status'])['application_height']
        question = question_id(chain, selected[0]['id'])
        ask = pending(call(0, ['ledger', 'ask', '--stdin'], {
            'source_record_id': selected[0]['id'], 'criteria_record_id': selected[1]['id'],
            'deadline_height': height + 48, 'bounty': 0, 'conflict_operators': []}, codes=(10,)))
        wait('zero_wallet_zero_bounty_question_committed', lambda: confirmed(0, ask))
        wait('question_known_by_future_five_live_validators', lambda: all(
            value.get('status') == 'open' for value in parallel(
                lambda i: call(i, ['ledger', 'get', '--question', question], codes=(0, 10)),
                range(2, 7))))
        # Neither the asker nor the real answer author is online. The finder has
        # no local keeper packet and ordinary IPC must perform distributed get.
        stage = 'offline_original_author_and_asker'
        finder_records = call(2, ['knowledge', 'status', '--room', ROOM])['records']
        check(all(row.get('id') != selected[2]['id'] for row in finder_records),
              'finder_answer_was_already_a_local_keeper_copy')
        nodes[0].stop()
        nodes[1].stop()
        answer = pending(call(2, ['ledger', 'answer', '--stdin'], {
            'question_id': question, 'source_record_id': selected[2]['id'],
            'beneficiary_peer_id': peers[1]}, codes=(10,)))
        wait('nonkeeper_finder_answer_committed_with_exactly_five_live_nodes',
             lambda: confirmed(2, answer))
        wait('answer_visible_to_all_three_judges', lambda: all(
            value.get('status') == 'open'
            and any(row.get('id') == selected[2]['id']
                    for row in value.get('question', {}).get('answers', []))
            for value in parallel(lambda i: call(
                i, ['ledger', 'get', '--question', question], codes=(0, 10)), range(3, 6))))
        stage = 'three_disinterested_judges_and_auto_reward'
        votes = parallel(lambda i: pending(call(i, ['ledger', 'vote', '--stdin'], {
            'question': question, 'answer': selected[2]['id'], 'verdict': 'satisfied'}, codes=(10,))),
            range(3, 6))
        wait('three_satisfaction_votes_auto_settle', lambda:
             all(confirmed(2, vote) for vote in votes)
             and call(2, ['ledger', 'get', '--question', question],
                      codes=(0, 10)).get('status') == 'closed')
        closed = call(2, ['ledger', 'get', '--question', question])['question']['outcome']
        check(closed.get('beneficiary_peer_id') == peers[1]
              and closed.get('submitted_by_peer_id') == peers[2], 'original_author_or_finder_changed')
        status = call(2, ['ledger', 'status'])
        paid = call(2, ['ledger', 'balance', '--peer-id', peers[1]])
        check(status.get('total_minted') == 1 and status.get('balance') == 0
              and paid.get('balance') == 1, 'reward_not_exactly_one_to_offline_author')
        blocks = call(2, ['ledger', 'blocks', '--from', str(closed['settled_height']), '--limit', '1'])
        check(blocks['blocks'][0].get('commit_votes') == 5, 'reward_commit_quorum_not_exactly_five')
        record('automatic_reward', {'minted_units': 1, 'offline_author_units': 1,
                                    'finder_units': 0, 'commit_votes': 5,
                                    'live_nodes': 5, 'judge_operators': 3})
        stage = 'returning_author_authenticated_sync'
        nodes[1].start()
        wait('returning_author_recovers_earned_unit', lambda:
             call(1, ['ledger', 'balance']).get('balance') == 1)
        stage = 'earned_unit_transfer'
        transfer = pending(call(1, ['ledger', 'transfer', '--stdin'],
                                {'to_peer_id': peers[2], 'amount': 1}, codes=(10,)))
        wait('earned_unit_transfer_committed', lambda: confirmed(1, transfer))
        wait('finder_receives_transferred_unit', lambda:
             call(2, ['ledger', 'balance']).get('balance') == 1)
        check(call(1, ['ledger', 'balance']).get('balance') == 0
              and call(2, ['ledger', 'status']).get('total_minted') == 1,
              'transfer_changed_supply_or_author_balance')
        record('final_balances_and_supply', {'original_author': 0, 'finder': 1, 'total_minted': 1})
        report['status'] = 'passed'
    except Exception as error:
        report['status'] = 'failed'
        report['failed_phase'] = stage
        report['failure'] = str(error) if isinstance(error, Failure) else 'fixture_execution_failed'
        if isinstance(error, Failure) and error.node_index is not None:
            report['failure_node_index'] = error.node_index
        diagnostics = []
        for i, node in enumerate(nodes):
            if node.daemon is None or node.daemon.poll() is not None:
                continue
            try:
                diagnostics.append({'node_index': i + 1,
                                    **safe_status(node.run(['ledger', 'status'], codes=(0, 10, 22)))})
            except Exception:
                diagnostics.append({'node_index': i + 1, 'state': 'unavailable'})
        report['failure_numeric_status'] = diagnostics
    finally:
        cleanup_errors = []
        if verified:
            checked = 0
            for host in range(4):
                node = next(node for node in nodes if node.c['physical_host'] == host)
                try:
                    check(node.binary_sha256() == node.c['binary_sha256'],
                          'native_binary_changed_during_fixture')
                    checked += 1
                except Exception:
                    cleanup_errors.append({'physical_host_index': host, 'operation': 'native_postcheck'})
            report['unchanged_native_artifact_count'] = checked
        stopped = []
        for index, node in reversed(list(enumerate(nodes))):
            try:
                node.stop()
                stopped.append(node)
            except Exception:
                cleanup_errors.append({'node_index': index + 1, 'operation': 'stop_fixture_daemon'})
        for tunnel in tunnels:
            try:
                tunnel.terminate()
                try:
                    tunnel.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    tunnel.kill()
                    tunnel.wait(timeout=5)
            except Exception:
                cleanup_errors.append({'operation': 'stop_fixture_tunnel'})
        removed = 0
        for node in stopped:
            try:
                node.remove_data()
                if node.initialized:
                    removed += 1
            except Exception:
                cleanup_errors.append({'node_index': nodes.index(node) + 1,
                                       'operation': 'remove_private_fixture_home'})
        for node in nodes:
            node.log.close()
        report['cleanup_errors'] = cleanup_errors
        report['cleanup_error_count'] = len(cleanup_errors)
        report['private_fixture_keys_removed'] = not cleanup_errors
        report['removed_fixture_home_count'] = removed
        report['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        if cleanup_errors:
            report['status'] = 'failed'
        FIXTURE.atomic_report(output, report)
    print(json.dumps({'status': report['status'], 'check_count': len(report['checks']),
                      'cleanup_error_count': report['cleanup_error_count']}), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
