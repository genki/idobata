#!/usr/bin/env python3
"""Opt-in, isolated four-host verification of the agent knowledge workflow.

Uses the inventory format and Node fixture helper from verify-peers.py. Binary
paths must already select the new SDK; this script never installs a binary or
changes production services. Inventory ports are deliberately replaced with
39130..39133. Only the fixture's daemons, tunnels and data are removed.
Acceptance requires every node's public native binary_sha256. The required
source digest is a manager-provided build label, not a CLI provenance proof.

The report contains counts and outcomes, never record bodies, queries, peer IDs,
addresses, certificates, synthetic token values or private exception messages.
Private daemon logs remain in a mode-0700 directory beside the output file.
"""

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import struct
import sys
import tempfile
import time
from types import SimpleNamespace


HELPER_PATH = Path(__file__).with_name('verify-peers.py')
SPEC = importlib.util.spec_from_file_location('idobata_peer_fixture', HELPER_PATH)
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)

ROOM = 'knowledge'
QUERY = '知識検証'
FIXTURE_PORTS = range(39130, 39134)
MUTATION_INTERVAL = 6.1
WAIT_SECONDS = 180
ID_PATTERN = re.compile(r'^[0-9a-f]{64}$')
AUTOMATION_ALGORITHM = 'sha256-u16le-sort-rotate-fold-v1'
AUTOMATION_CASES = 24
AUTOMATION_VALUES = 16
AUTOMATION_PACKET_BYTES = 16 * 1024


class VerificationFailure(RuntimeError):
    """A static, body-free failure label that may safely enter the report."""

    def __init__(self, label, *, node_index=None, phase=None):
        super().__init__(label)
        self.node_index = node_index
        self.phase = phase


def check(condition, label):
    if not condition:
        raise VerificationFailure(label)


def parallel(function, values):
    with ThreadPoolExecutor(max_workers=4) as executor:
        return list(executor.map(function, values))


def fixture_node_config(config, index, port):
    """本番homeを候補inventoryから引き継がず、一時領域の子だけを使う。"""
    check(isinstance(config, dict), 'invalid_inventory_node')
    platform = config.get('platform')
    root = config.get('root')
    binary = config.get('binary')
    check(platform in ['linux', 'macos', 'windows'] and isinstance(root, str)
          and isinstance(binary, str) and binary
          and not any(ord(character) < 32 for character in binary),
          'invalid_fixture_inventory_fields')
    root = root.replace('\\', '/').rstrip('/')
    check(not any(part in ['.', '..'] for part in root.split('/'))
          and not any(ord(character) < 32 for character in root),
          'invalid_fixture_root')
    if platform == 'windows':
        temporary = re.fullmatch(
            r'[a-z]:/(?:users/[^/]+/appdata/local/temp|windows/temp)/[^/]+(?:/[^/]+)*',
            root.lower()) is not None
    else:
        temporary = root.startswith('/tmp/') or root.startswith('/private/tmp/')
    check(temporary, 'fixture_root_must_be_temporary_child')
    value = {'platform': platform, 'binary': binary, 'root': root,
             'name': 'node-' + str(index + 1), 'port': port}
    if config.get('ssh'):
        check(isinstance(config['ssh'], str)
              and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', config['ssh']),
              'invalid_fixture_ssh_alias')
        value['ssh'] = config['ssh']
    expected = config.get('binary_sha256')
    if expected is not None:
        check(isinstance(expected, str) and ID_PATTERN.fullmatch(expected),
              'invalid_expected_native_binary_hash')
        value['binary_sha256'] = expected
    return value


def fixture_file_path(home, path, *, windows=False):
    """Uploads may address one ordinary file directly inside this fixture home."""
    check(isinstance(path, str), 'invalid_fixture_upload_path')
    normalized = path.replace('\\', '/')
    prefix = home.replace('\\', '/').rstrip('/') + '/'
    compared = normalized.lower() if windows else normalized
    expected = prefix.lower() if windows else prefix
    check(compared.startswith(expected), 'fixture_upload_outside_home')
    leaf = normalized[len(prefix):]
    check(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', leaf) is not None
          and leaf not in ['.', '..'], 'invalid_fixture_upload_filename')
    return prefix + leaf


def public_task_cases(seed):
    """Independent Python implementation of the published fixed task generator."""
    check(isinstance(seed, str) and ID_PATTERN.fullmatch(seed), 'invalid_automation_seed')
    raw_seed = bytes.fromhex(seed)
    cases = []
    for index in range(AUTOMATION_CASES):
        digest = hashlib.sha256(b'idobata.automation.tasks.v1\0' + raw_seed
                                + struct.pack('<I', index)).digest()
        cases.append({
            'index': index,
            'values': [value % 997 for value in struct.unpack('<16H', digest)],
            'sort': ['ascending', 'descending', 'none'][index % 3],
            'rotate_left': index % AUTOMATION_VALUES,
            'initial': index + 1,
            'multiplier': 33 + 2 * (index % 5),
        })
    return cases


def solve_automation_challenge(value, *, subject, room_id, authority, members, purpose):
    """Test-only solver; never execute instructions received as arbitrary text."""
    check(value.get('status') == 'automation_challenge_required'
          and value.get('enqueued') is False and value.get('stored') is False,
          'invalid_automation_challenge_status')
    check(value.get('untrusted') is True, 'challenge_missing_untrusted_marker')
    check('assurance' not in value, 'pending_challenge_claimed_assurance')
    specification = value.get('task_spec')
    check(isinstance(specification, dict)
          and specification.get('algorithm') == AUTOMATION_ALGORITHM
          and specification.get('version') == 1
          and specification.get('case_count') == AUTOMATION_CASES
          and specification.get('values_per_case') == AUTOMATION_VALUES
          and specification.get('assurance') == 'automation_tested',
          'unsupported_automation_task_spec')
    packet = value.get('challenge')
    check(isinstance(packet, dict) and set(packet) == {'challenge', 'certificate'},
          'invalid_automation_challenge_packet')
    check(len(json.dumps(packet, ensure_ascii=False, separators=(',', ':')).encode())
          <= AUTOMATION_PACKET_BYTES, 'oversized_automation_challenge')
    signed = packet.get('challenge')
    check(isinstance(signed, dict) and set(signed) == {'signed', 'public_key', 'signature'},
          'invalid_signed_automation_challenge')
    challenge = signed.get('signed')
    check(isinstance(challenge, dict) and set(challenge) == {
        'version', 'id', 'room_id', 'subject_peer_id', 'action_digest',
        'purpose', 'issued_at', 'expires_at', 'seed'}, 'invalid_automation_fields')
    check(challenge.get('version') == 1
          and isinstance(challenge.get('id'), str) and ID_PATTERN.fullmatch(challenge['id'])
          and isinstance(challenge.get('action_digest'), str)
          and ID_PATTERN.fullmatch(challenge['action_digest'])
          and challenge.get('subject_peer_id') == subject
          and challenge.get('room_id') == room_id
          and challenge.get('purpose') == purpose,
          'automation_challenge_binding_changed')
    issued = challenge.get('issued_at')
    expires = challenge.get('expires_at')
    check(type(issued) is int and type(expires) is int
          and 0 <= issued < expires <= 9_007_199_254_740_991
          and expires - issued <= 120, 'invalid_automation_challenge_lifetime')
    issuer = members.get(signed.get('public_key'))
    check(issuer is not None and issuer != subject, 'challenge_not_issued_by_other_member')
    certificate = packet.get('certificate')
    check(isinstance(certificate, dict) and certificate.get('authority_peer_id') == authority,
          'automation_authority_changed')
    room = certificate.get('certificate', {}).get('signed', {})
    check(room.get('room_id') == room_id
          and room.get('knowledge_automation_required') is True,
          'automation_room_policy_changed')
    cases = public_task_cases(challenge.get('seed'))
    check(value.get('tasks') == cases, 'public_automation_tasks_do_not_match_seed')
    answers = []
    for case in cases:
        values = list(case['values'])
        if case['sort'] != 'none':
            values.sort(reverse=case['sort'] == 'descending')
        offset = case['rotate_left']
        values = values[offset:] + values[:offset]
        accumulated = case['initial']
        for position, item in enumerate(values):
            accumulated = (accumulated * case['multiplier'] + (position + 1) * item) & 0xffffffff
            rotation = (case['index'] + position) % 31 + 1
            accumulated = ((accumulated << rotation)
                           | (accumulated >> (32 - rotation))) & 0xffffffff
        answers.append(accumulated)
    answer = {'challenge': packet, 'answers': answers}
    check(len(json.dumps(answer, ensure_ascii=False, separators=(',', ':')).encode())
          <= AUTOMATION_PACKET_BYTES, 'oversized_automation_answer')
    return answer


def solver_self_test():
    """No SDK execution, hosts, credentials or fixture processes are involved."""
    room_id = 'a' * 64
    payload = {
        'version': 1, 'id': 'b' * 64, 'room_id': room_id,
        'subject_peer_id': 'subject', 'action_digest': 'c' * 64,
        'purpose': 'publish', 'issued_at': 10_000, 'expires_at': 10_120,
        'seed': '0' * 64,
    }
    challenge = {
        'status': 'automation_challenge_required', 'enqueued': False,
        'stored': False, 'untrusted': True,
        'task_spec': {'algorithm': AUTOMATION_ALGORITHM, 'version': 1,
                      'case_count': AUTOMATION_CASES, 'values_per_case': AUTOMATION_VALUES,
                      'assurance': 'automation_tested'},
        'tasks': public_task_cases(payload['seed']),
        'challenge': {
            'challenge': {'signed': payload, 'public_key': 'issuer-key', 'signature': 'test-only'},
            'certificate': {'authority_peer_id': 'authority', 'certificate': {'signed': {
                'room_id': room_id, 'knowledge_automation_required': True}}},
        },
    }
    arguments = {'subject': 'subject', 'room_id': room_id, 'authority': 'authority',
                 'members': {'issuer-key': 'issuer'}, 'purpose': 'publish'}
    solved = solve_automation_challenge(challenge, **arguments)
    check(solved['answers'] == [
        241154151, 3547265955, 1116561072, 2108799716, 2999146339, 4136467445,
        2520180127, 1542230348, 1890627663, 2315501570, 3496633469, 143891129,
        1987887498, 2998518041, 4212433332, 3003736209, 921108977, 2091693371,
        1883997569, 2008552011, 3831226734, 94727809, 1398741250, 856323620],
        'independent_automation_golden_vector_changed')
    invalid = []
    for path, replacement in [
        (('task_spec', 'algorithm'), 'execute-untrusted-text'),
        (('task_spec', 'case_count'), 25),
        (('challenge', 'challenge', 'signed', 'seed'), '0' * 63),
        (('challenge', 'challenge', 'signed', 'purpose'), 'evaluate'),
        (('challenge', 'challenge', 'signed', 'subject_peer_id'), 'another-subject'),
        (('challenge', 'challenge', 'signed', 'expires_at'), 10_121),
        (('challenge', 'challenge', 'public_key'), 'unknown-key'),
        (('challenge', 'certificate', 'authority_peer_id'), 'another-authority'),
    ]:
        changed = copy.deepcopy(challenge)
        target = changed
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        invalid.append(changed)
    changed = copy.deepcopy(challenge)
    changed['tasks'][0]['values'][0] += 1
    invalid.append(changed)
    changed = copy.deepcopy(challenge)
    changed['assurance'] = 'automation_tested'
    invalid.append(changed)
    for changed in invalid:
        try:
            solve_automation_challenge(changed, **arguments)
        except VerificationFailure:
            continue
        raise VerificationFailure('invalid_automation_challenge_was_accepted')
    mutation_roundtrips = 0
    for purpose in ['publish', 'evaluate']:
        offered = copy.deepcopy(challenge)
        offered['challenge']['challenge']['signed']['purpose'] = purpose
        node = SimpleNamespace(
            peer_id='subject', room_id=room_id, authority='authority',
            member_keys={'issuer-key': 'issuer'}, home='/unused-test-fixture',
            automation_counts={'publish': 0, 'evaluate': 0})
        written = {}
        calls = []
        removed = []
        body = {'test': 'unchanged action input'}
        base_args = ['knowledge', purpose, '--room', ROOM, '--stdin']

        def mutation_request(args, data, codes):
            check(data == body, 'proof_resubmission_changed_stdin')
            calls.append((list(args), codes))
            if len(calls) == 1:
                check(args == base_args and codes == (31,), 'challenge_exit_not_required')
                return offered
            check(codes == (0,) and args[:-2] == base_args and args[-2] == '--proof',
                  'proof_not_submitted_to_same_action')
            answer = json.loads(written[args[-1]])
            check(answer['challenge'] == offered['challenge']
                  and answer['answers'] == solved['answers'], 'wrong_proof_file_shape')
            return {'status': 'accepted', 'id': 'c' * 64, 'stored': True,
                    'evaluation_applied': True, 'assurance': 'automation_tested'}

        node.mutation_request = mutation_request
        node.put = lambda path, contents: written.__setitem__(path, contents)
        node.remove_fixture_file = removed.append
        node.run = lambda _args: {
            'replication_factor': 3, 'records': [], 'objects': 0,
            'bytes': 64, 'quota_bytes': 64 * 1024 * 1024}
        FixtureNode.mutate(node, base_args, body)
        check(len(calls) == 2 and len(removed) == 1
              and node.automation_counts[purpose] == 1,
              'automation_mutation_roundtrip_incomplete')
        mutation_roundtrips += 1
    for platform, path in [
        ('linux', '/var/lib/idobata'),
        ('macos', '/Library/Application Support/idobata'),
        ('windows', 'C:/ProgramData/idobata'),
        ('linux', '/tmp/../var/lib/idobata'),
    ]:
        try:
            fixture_node_config({'platform': platform, 'root': path,
                                 'binary': '/unused/candidate'}, 0, 39130)
        except VerificationFailure:
            continue
        raise VerificationFailure('production_home_accepted_as_fixture_root')
    for platform, path in [
        ('linux', '/tmp/idobata-v03-fixture'),
        ('macos', '/private/tmp/idobata-v03-fixture'),
        ('windows', 'C:/Users/fixture/AppData/Local/Temp/idobata-v03-fixture'),
    ]:
        selected = fixture_node_config({'platform': platform, 'root': path,
                                        'binary': '/unused/candidate',
                                        'home': 'production-home-sentinel',
                                        'identity': 'private-metadata-sentinel'}, 0, 39130)
        check('home' not in selected and 'identity' not in selected,
              'production_metadata_retained_in_fixture_config')
    upload_home = 'C:/Users/fixture/AppData/Local/Temp/idobata-fixture/node-test'
    for path in [upload_home + '/../escape.json', upload_home + '/nested/file.json',
                 upload_home + '/answer.json:stream', upload_home + '/answer\n.json',
                 upload_home + '-other/answer.json', 'C:/ProgramData/answer.json']:
        try:
            fixture_file_path(upload_home, path, windows=True)
        except VerificationFailure:
            continue
        raise VerificationFailure('unsafe_fixture_upload_path_accepted')
    from unittest import mock
    upload_source = []
    upload_node = SimpleNamespace(win=True, host='test-fixture-host', home=upload_home)
    upload_bytes = b'safe-fixture-data' * 150

    def mock_sftp(argv, **options):
        check(argv[:2] == ['scp', '-q'] and options.get('stdin') == subprocess.DEVNULL,
              'fixture_upload_not_binary_sftp')
        check(argv[-1] == 'test-fixture-host:' + upload_home + '/answer.json'
              and sum(len(item) for item in argv) < 1024,
              'fixture_upload_payload_embedded_in_command')
        path = Path(argv[-2])
        upload_source.append(path)
        check(path.stat().st_mode & 0o777 == 0o600 and path.read_bytes() == upload_bytes,
              'fixture_upload_tempfile_not_private_or_exact')
        return SimpleNamespace(returncode=0)

    with mock.patch.object(subprocess, 'run', side_effect=mock_sftp):
        FixtureNode.put(upload_node, upload_home + '/answer.json', upload_bytes)
    check(len(upload_source) == 1 and not upload_source[0].exists(),
          'fixture_upload_tempfile_not_removed')
    return {'golden_answer_count': len(solved['answers']),
            'rejected_invalid_challenge_count': len(invalid),
            'mock_challenge_proof_roundtrip_count': mutation_roundtrips,
            'rejected_unsafe_fixture_root_count': 4,
            'rejected_unsafe_upload_path_count': 6,
            'mock_private_sftp_upload_count': 1,
            'replication_diagnostic_cases': replication_summary_self_test(),
            'case_a_guard_checks': case_a_self_test()}


class FixtureNode(HELPERS.Node):
    """Keep helper lifecycle operations, suppress raw CLI output on failures."""

    def __init__(self, config, logs, run_id):
        super().__init__(config, logs, run_id)
        os.chmod(logs / (self.name + '.log'), 0o600)
        self.private_logs = logs
        self.fixture_index = int(self.name.removeprefix('node-'))
        self.phase = 'cli'
        self.last_mutation = 0.0
        self.automation_counts = {'publish': 0, 'evaluate': 0}

    def binary_sha256(self):
        """Read only the public native executable, never identity/storage keys."""
        if self.win:
            result = self.powershell(
                '(Get-FileHash -LiteralPath ' + HELPERS.ps_quote(self.binary)
                + ' -Algorithm SHA256).Hash.ToLowerInvariant()', timeout=45)
        elif self.host:
            result = self.shell("python3 - <<'HASH'\nimport hashlib\n"
                                + 'digest=hashlib.sha256()\n'
                                + f'with open({self.binary!r},"rb") as source:\n'
                                + ' for chunk in iter(lambda:source.read(1048576),b""):\n'
                                + '  digest.update(chunk)\nprint(digest.hexdigest())\nHASH',
                                timeout=45)
        else:
            digest = hashlib.sha256()
            with open(self.binary, 'rb') as source:
                for chunk in iter(lambda: source.read(1048576), b''):
                    digest.update(chunk)
            return digest.hexdigest()
        if result.returncode != 0:
            self.private_diagnostic(result)
            raise VerificationFailure('native_binary_hash_failed', node_index=self.fixture_index)
        try:
            value = result.stdout.decode('utf-8-sig').strip()
        except UnicodeError:
            raise VerificationFailure('invalid_native_binary_hash',
                                      node_index=self.fixture_index) from None
        check(ID_PATTERN.fullmatch(value), 'invalid_native_binary_hash')
        return value

    def private_diagnostic(self, result):
        # stdout/stderr may contain a rejected body. Never include them in JSON.
        stamp = str(time.time_ns())
        for stream in ['stdout', 'stderr']:
            raw = getattr(result, stream, None)
            if raw:
                path = self.private_logs / (self.name + '-' + stamp + '.' + stream + '.log')
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as destination:
                    destination.write(raw if isinstance(raw, bytes) else raw.encode())

    def run(self, args, data=None, codes=(0,), timeout=35):
        if isinstance(data, str):
            data = data.encode()
        if len(args) >= 2 and args[0] == 'knowledge':
            if not hasattr(self, 'knowledge_cli_counts'):
                self.knowledge_cli_counts = {}
            self.knowledge_cli_counts[args[1]] = self.knowledge_cli_counts.get(args[1], 0) + 1
        result = subprocess.run(self.argv(args), input=data, capture_output=True,
                                timeout=timeout)
        if result.returncode not in codes:
            self.private_diagnostic(result)
            raise VerificationFailure('unexpected_cli_exit', node_index=self.fixture_index,
                                      phase=self.phase)
        try:
            value = json.loads(result.stdout.decode('utf-8-sig'))
        except (ValueError, UnicodeError):
            self.private_diagnostic(result)
            raise VerificationFailure('invalid_cli_json', node_index=self.fixture_index,
                                      phase=self.phase) from None
        check(isinstance(value, dict), 'invalid_cli_json_object')
        return value

    def put(self, path, contents):
        path = fixture_file_path(self.home, path, windows=self.win)
        if not self.win:
            return super().put(path, contents)
        check(bool(self.host), 'windows_fixture_requires_ssh')
        raw = contents.encode() if isinstance(contents, str) else contents
        check(isinstance(raw, bytes), 'invalid_fixture_upload_contents')
        # Windows cmd.exe rejects a large PowerShell EncodedCommand before the
        # payload is decoded. OpenSSH scp uses its binary SFTP transport instead.
        descriptor, local_path = tempfile.mkstemp(prefix='idobata-fixture-upload-')
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, 'wb') as destination:
                destination.write(raw)
            result = subprocess.run(
                ['scp', '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12',
                 local_path, self.host + ':' + path],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
            if result.returncode != 0:
                self.private_diagnostic(result)
                raise VerificationFailure('fixture_sftp_upload_failed',
                                          node_index=self.fixture_index, phase=self.phase)
        finally:
            Path(local_path).unlink(missing_ok=True)

    def mutation_request(self, args, data, codes):
        delay = self.last_mutation + MUTATION_INTERVAL - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self.last_mutation = time.monotonic()
        return self.run(args, json.dumps(data, ensure_ascii=False), codes=codes)

    def mutate(self, args, data):
        try:
            return FixtureNode._mutate(self, args, data)
        except Exception as error:
            if isinstance(error, VerificationFailure):
                error.node_index = getattr(self, 'fixture_index', None)
                error.phase = getattr(self, 'phase', 'mutation')
                raise
            raise VerificationFailure('fixture_mutation_subprocess_failure'
                                      if isinstance(error, subprocess.SubprocessError)
                                      else 'fixture_mutation_internal_failure',
                                      node_index=getattr(self, 'fixture_index', None),
                                      phase=getattr(self, 'phase', 'mutation')) from None
        finally:
            self.phase = 'cli'

    def _mutate(self, args, data):
        purpose = args[1]
        check(purpose in self.automation_counts, 'unsupported_fixture_mutation')
        # Both the initial request and proof resubmission consume a rate token.
        # Space every CLI mutation by 6.1 seconds, rather than only each pair.
        self.phase = 'challenge'
        challenge = self.mutation_request(args, data, codes=(31,))
        self.phase = 'solve_public_tasks'
        answer = solve_automation_challenge(
            challenge, subject=self.peer_id, room_id=self.room_id,
            authority=self.authority, members=self.member_keys, purpose=purpose)
        if purpose == 'publish':
            self.phase = 'pending_storage_status'
            pending_id = answer['challenge']['challenge']['signed']['action_digest']
            local = status(self)
            check(all(item['id'] != pending_id for item in local['records']),
                  'challenge_stored_record_before_certification')
        proof_path = self.home + '/automation-answer-' + str(sum(self.automation_counts.values())) + '.json'
        self.phase = 'put_answer'
        self.put(proof_path, json.dumps(answer, ensure_ascii=False, separators=(',', ':')))
        try:
            self.phase = 'proof_resubmit'
            result = self.mutation_request(args + ['--proof', proof_path], data, codes=(0,))
        finally:
            pending_phase = self.phase
            self.phase = 'answer_cleanup'
            self.remove_fixture_file(proof_path)
            self.phase = pending_phase
        self.phase = 'accepted_result'
        check(result.get('status') == 'accepted'
              and result.get('assurance') == 'automation_tested',
              'accepted_action_missing_automation_receipt')
        if purpose == 'publish':
            check(result.get('id') == pending_id, 'certified_publish_digest_changed')
        else:
            check(result.get('evaluation_applied') is True, 'certified_evaluation_not_applied')
        self.automation_counts[purpose] += 1
        return result

    def remove_fixture_file(self, path):
        path = fixture_file_path(self.home, path, windows=self.win)
        if self.win:
            quoted = HELPERS.ps_quote(path)
            result = self.powershell(f'Remove-Item -LiteralPath {quoted} -Force')
        elif self.host:
            result = self.shell('rm -f -- ' + shlex.quote(path))
        else:
            Path(path).unlink(missing_ok=True)
            return
        check(result.returncode == 0, 'fixture_answer_cleanup_failed')

    def stop(self):
        if self.daemon is None:
            return
        if not self.host:
            super().stop()
            return
        # An SSH client's exit does not establish that its remote daemon stopped.
        # Match the exact fixture home even when the helper's SSH child has died.
        if self.win:
            quote = HELPERS.ps_quote
            script = f"""
$fixtureProcesses=@(Get-CimInstance Win32_Process -Filter "Name='idobata.exe'" | Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath.Replace('\\','/') -eq {quote(self.binary)} -and $_.CommandLine -and $_.CommandLine.Replace('\\','/').Contains({quote(self.home)}) -and $_.CommandLine.Contains('daemon') }})
if ($fixtureProcesses.Count -gt 1) {{ throw 'ambiguous fixture process' }}
$fixtureProcesses | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}
"""
            result = self.powershell(script)
        else:
            expected = shlex.join([self.binary, '--home', self.home, 'daemon'])
            script = f"""python3 - <<'STOP'
from pathlib import Path
import os,signal,subprocess,time
path=Path({self.home + '/daemon.pid'!r})
if path.exists():
 pid=int(path.read_text())
 def current():
  result=subprocess.run(['ps','-p',str(pid),'-o','command='],capture_output=True,text=True)
  return result.stdout.strip() if result.returncode==0 else ''
 command=current()
 if command and command!={expected!r}:
  raise SystemExit('unexpected fixture process')
 if command:
  os.kill(pid,signal.SIGINT)
  deadline=time.monotonic()+12
  while current()=={expected!r} and time.monotonic()<deadline:time.sleep(0.1)
  if current()=={expected!r}:raise SystemExit('fixture did not stop')
STOP"""
            result = self.shell(script)
        check(result.returncode == 0, 'fixture_stop_failed')
        try:
            self.daemon.wait(timeout=12)
        except subprocess.TimeoutExpired:
            self.daemon.terminate()
            self.daemon.wait(timeout=5)

    def remove_data(self):
        if not self.initialized:
            return
        check(self.daemon is None or self.daemon.poll() is not None,
              'cannot_remove_active_fixture')
        # init may have failed after creating keys. Cleanup is idempotent and
        # covers that partially initialized fixture too.
        if self.win:
            path = HELPERS.ps_quote(self.home)
            result = self.powershell(
                f'if (Test-Path -LiteralPath {path}) {{ '
                f'Remove-Item -LiteralPath {path} -Recurse -Force }}')
        elif self.host:
            result = self.shell('rm -rf -- ' + shlex.quote(self.home))
        else:
            import shutil
            if Path(self.home).exists():
                shutil.rmtree(self.home)
            return
        check(result.returncode == 0, 'fixture_data_cleanup_failed')

    def knowledge_encrypted(self, text):
        path = self.home + '/knowledge.enc'
        if self.win:
            quote = HELPERS.ps_quote
            result = self.powershell(
                f'$data=[IO.File]::ReadAllBytes({quote(path)}); '
                f'if ($data.Length -eq 0) {{ exit 1 }}; '
                f'$text=[Text.Encoding]::UTF8.GetString($data); '
                f'if ($text.Contains({quote(text)})) {{ exit 1 }}')
            return result.returncode == 0
        if self.host:
            script = f"""python3 - <<'CHECK'
from pathlib import Path
data=Path({path!r}).read_bytes()
raise SystemExit(0 if data and {text.encode()!r} not in data else 1)
CHECK"""
            return self.shell(script).returncode == 0
        data = Path(path).read_bytes()
        return bool(data) and text.encode() not in data


def status(node):
    value = node.run(['knowledge', 'status', '--room', ROOM])
    check(value.get('replication_factor') == 3, 'wrong_replication_factor')
    check(isinstance(value.get('records'), list), 'missing_local_record_inventory')
    check(type(value.get('bytes')) is int
          and type(value.get('quota_bytes')) is int
          and 0 <= value['bytes'] <= value['quota_bytes'] <= 64 * 1024 * 1024,
          'invalid_quota_accounting')
    check(value.get('objects') == len(value['records']), 'wrong_object_count')
    return value


def wait_peer_readiness(nodes, timeout=WAIT_SECONDS):
    """IPCの起動と、認証済みP2P接続の準備を区別して待つ。"""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        check(remaining > 0, 'authenticated_peer_readiness_deadline')

        def connected(node):
            try:
                value = node.run(['info'], timeout=min(15, remaining))
            except (RuntimeError, subprocess.SubprocessError):
                return 0
            count = value.get('connected_peers')
            return count if type(count) is int and count >= 0 else 0

        counts = parallel(connected, nodes)
        if all(count >= 1 for count in counts):
            return counts
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def record_inventory(snapshots):
    result = {}
    for index, snapshot in enumerate(snapshots):
        local_ids = set()
        for record in snapshot['records']:
            record_id = record.get('id', '')
            check(ID_PATTERN.fullmatch(record_id), 'invalid_record_id')
            check(record_id not in local_ids, 'duplicate_local_record')
            local_ids.add(record_id)
            result.setdefault(record_id, []).append((index, record))
    return result


def require_nonkeeper_authors(fixtures, copies):
    selected = [fixture for fixture in fixtures
                if fixture['author_index'] not in {
                    index for index, _ in copies[fixture['id']]}]
    check(selected, 'fixture_placement_insufficient')
    return selected


def replica_complete(snapshots, fixtures, peer_ids):
    inventory = record_inventory(snapshots)
    if set(inventory) != {fixture['id'] for fixture in fixtures}:
        return False
    for fixture in fixtures:
        copies = inventory[fixture['id']]
        if len(copies) != 3:
            return False
        assigned = None
        for index, record in copies:
            keepers = record.get('assigned_keepers')
            check(isinstance(keepers, list), 'missing_assigned_keepers')
            check(len(keepers) == len(set(keepers)) == 3
                  and set(keepers) <= set(peer_ids), 'invalid_keeper_assignment')
            if assigned is None:
                assigned = set(keepers)
            check(set(keepers) == assigned, 'inconsistent_keeper_assignment')
            if record.get('local_role') != 'keeper' or record.get('staging') is not False:
                return False
            check(peer_ids[index] in assigned, 'unexpected_persistent_nonkeeper')
        if {peer_ids[index] for index, _ in copies} != assigned:
            return False
    return True


def replication_summary(snapshots, fixtures, peer_ids, observations):
    """Only fixture indices, counts and static classifications may be public."""
    inventory = record_inventory(snapshots)
    histogram = {str(count): 0 for count in range(5)}
    records = []
    for fixture_index, fixture in enumerate(fixtures):
        copies = inventory.get(fixture['id'], [])
        histogram[str(len(copies))] = histogram.get(str(len(copies)), 0) + 1
        assignments = [set(row.get('assigned_keepers', [])) for _, row in copies]
        consistent = bool(assignments) and all(value == assignments[0]
                                              for value in assignments)
        assigned_matches = (consistent and len(assignments[0]) == 3
                            and assignments[0] == {peer_ids[index] for index, _ in copies})
        records.append({
            'record_index': fixture_index + 1,
            'copy_count': len(copies),
            'staging_count': sum(row.get('staging') is True for _, row in copies),
            'assigned_matches': assigned_matches,
            'copies': [{'node_index': index + 1,
                        'staging': row.get('staging') is True,
                        'keeper_role': row.get('local_role') == 'keeper',
                        'replica_ack_count': len(row.get('replica_acks', [])),
                        'replication_complete': row.get('replication_complete') is True}
                       for index, row in copies],
        })
    node_rows = []
    clocks = []
    for index, (snapshot, observation) in enumerate(zip(snapshots, observations)):
        info = observation.get('info', {})
        knowledge = info.get('knowledge', {})
        row = {'node_index': index + 1, 'objects': len(snapshot['records']),
               'staging_count': sum(record.get('staging') is True
                                    for record in snapshot['records']),
               'info_available': bool(info)}
        for field in ['connected_peers', 'outbound_attempts', 'outbound_failures',
                      'inbound_requests', 'uptime_seconds']:
            if type(info.get(field)) is int:
                row[field] = info[field]
        for field in ['pending_replications', 'pending_repairs', 'pending_inventory_pages',
                      'pending_automation', 'expired_background_requests']:
            if type(knowledge.get(field)) is int:
                row[field] = knowledge[field]
        if type(observation.get('unix_time')) is int:
            clocks.append(observation['unix_time'])
        node_rows.append(row)
    return {'distinct_records': len(inventory),
            'total_copies': sum(len(copies) for copies in inventory.values()),
            'copy_count_histogram': histogram,
            'unexpected_record_count': len(set(inventory) - {row['id'] for row in fixtures}),
            'records': records, 'nodes': node_rows,
            'transport_counter_scope': 'legacy_messages_only',
            'clock_observed_host_count': len(clocks),
            'clock_spread_seconds': max(clocks) - min(clocks) if clocks else None}


def replication_summary_self_test():
    peers = ['private-peer-' + str(index) for index in range(4)]
    fixture = {'id': 'f' * 64}
    snapshots = [{'records': []} for _ in peers]
    row = {'id': fixture['id'], 'assigned_keepers': peers[:3],
           'replica_acks': peers[:1], 'local_role': 'keeper', 'staging': True,
           'replication_complete': False, 'unused': 'PRIVATE-BODY-SENTINEL'}
    for snapshot in snapshots[:2]:
        snapshot['records'].append(copy.deepcopy(row))
    observations = [{'info': {'connected_peers': 3, 'knowledge': {'pending_repairs': 2}},
                     'unix_time': 100 + index} for index in range(4)]
    missing = replication_summary(snapshots, [fixture], peers, observations)
    check(missing['copy_count_histogram']['2'] == 1
          and missing['records'][0]['assigned_matches'] is False,
          'diagnostic_missing_copy_classification')
    snapshots[2]['records'].append(copy.deepcopy(row))
    staged = replication_summary(snapshots, [fixture], peers, observations)
    check(staged['records'][0]['copy_count'] == 3
          and staged['records'][0]['assigned_matches'] is True
          and staged['records'][0]['staging_count'] == 3
          and staged['records'][0]['copies'][0]['replica_ack_count'] == 1,
          'diagnostic_staging_classification')
    snapshots[3]['records'].append(copy.deepcopy(row))
    extra = replication_summary(snapshots, [fixture], peers, observations)
    check(extra['copy_count_histogram']['4'] == 1
          and extra['records'][0]['assigned_matches'] is False
          and extra['clock_spread_seconds'] == 3,
          'diagnostic_extra_copy_classification')
    public = json.dumps(extra)
    check(fixture['id'] not in public and all(peer not in public for peer in peers)
          and 'PRIVATE-BODY-SENTINEL' not in public,
          'diagnostic_private_metadata_leak')
    return 3


def diagnose_replication(nodes, fixtures, peer_ids, snapshots):
    def observe(node):
        value = {}
        try:
            value['info'] = node.run(['info'], timeout=15)
        except (RuntimeError, subprocess.SubprocessError):
            value['info_error'] = 'unavailable'
        try:
            result = (node.powershell('[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()', timeout=15)
                      if node.win else node.shell('date +%s', timeout=15))
            if result.returncode == 0:
                value['unix_time'] = int(result.stdout.decode('utf-8-sig').strip())
        except (ValueError, UnicodeError, RuntimeError, subprocess.SubprocessError):
            value['clock_error'] = 'unavailable'
        return value

    observations = parallel(observe, nodes)
    # IDs, peer IDs and complete metadata stay private; no record bodies are queried.
    private = {'snapshots': snapshots, 'observations': observations,
               'peer_ids': peer_ids,
               'record_ids': [fixture['id'] for fixture in fixtures]}
    atomic_report(nodes[0].private_logs / ('replication-' + str(time.time_ns()) + '.json'),
                  private)
    return replication_summary(snapshots, fixtures, peer_ids, observations)


def wait_replicas(nodes, fixtures, peer_ids):
    deadline = time.monotonic() + WAIT_SECONDS
    while True:
        snapshots = parallel(status, nodes)
        if replica_complete(snapshots, fixtures, peer_ids):
            return snapshots
        if time.monotonic() >= deadline:
            failure = VerificationFailure('replication_deadline')
            failure.replication_diagnostics = diagnose_replication(
                nodes, fixtures, peer_ids, snapshots)
            raise failure
        time.sleep(1)


def search(node, query=QUERY, *, explore=True):
    args = ['knowledge', 'search', '--room', ROOM, '--query', query, '--limit', '10']
    if explore:
        args.append('--explore')
    value = node.run(args)
    check(isinstance(value.get('hits'), list), 'missing_search_hits')
    return value


def verified_get(node, fixture):
    value = node.run(['knowledge', 'get', '--room', ROOM, '--id', fixture['id']])
    if value.get('found') is not True:
        return None
    record = value.get('record')
    check(isinstance(record, dict), 'missing_get_record')
    check(record.get('id') == fixture['id'], 'get_returned_another_record')
    for key in ('problem', 'solution', 'context', 'references', 'kind'):
        check(record.get(key) == fixture['input'][key], 'get_changed_record_content')
    check(record.get('author_peer_id') == fixture['author'], 'relayer_replaced_author')
    check(record.get('public') is False, 'private_knowledge_became_public')
    check(value.get('untrusted') is True or record.get('untrusted') is True,
          'missing_untrusted_get_marker')
    check(type(value.get('responded_peers')) is int and value['responded_peers'] >= 1,
          'get_had_no_remote_peer_response')
    return value


def useful_votes(value):
    quality = value.get('quality')
    check(isinstance(quality, dict) and type(quality.get('useful_votes')) is int
          and quality['useful_votes'] >= 0, 'missing_independent_useful_vote_count')
    return quality['useful_votes']


def case_a_self_test():
    """Exercise new acceptance guards using synthetic values and mocked I/O."""
    from unittest import mock
    config = {'platform': 'linux', 'root': '/tmp/idobata-knowledge-fixtures',
              'binary': '/tmp/candidate-idobata'}
    rejected = 0
    for alias in ['-oProxyCommand=unexpected', 'host name', 'host\nname']:
        try:
            fixture_node_config({**config, 'ssh': alias}, 0, 39130)
        except VerificationFailure:
            rejected += 1
        else:
            raise VerificationFailure('unsafe_ssh_alias_was_accepted')
    for value in [True, 'a' * 63, 'A' * 64]:
        try:
            fixture_node_config({**config, 'binary_sha256': value}, 0, 39130)
        except VerificationFailure:
            rejected += 1
        else:
            raise VerificationFailure('invalid_native_hash_was_accepted')
    selected = fixture_node_config({**config, 'binary_sha256': 'a' * 64}, 0, 39130)
    check(selected['binary_sha256'] == 'a' * 64, 'expected_native_hash_was_discarded')
    copies = {'a' * 64: [(0, {}), (1, {}), (2, {})]}
    check(len(require_nonkeeper_authors([{'id': 'a' * 64, 'author_index': 3}], copies)) == 1,
          'nonkeeper_author_fixture_not_selected')
    try:
        require_nonkeeper_authors([{'id': 'a' * 64, 'author_index': 0}], copies)
    except VerificationFailure as error:
        check(str(error) == 'fixture_placement_insufficient', 'wrong_placement_failure_class')
    else:
        raise VerificationFailure('keeper_author_fallback_was_accepted')
    check(useful_votes({'quality': {'useful_votes': 0},
                        'reviews': [{'verdict': 'useful'}]}) == 0,
          'physical_review_was_counted_as_operator_support')
    for value in [{'reviews': [{'verdict': 'useful'}]},
                  {'quality': {'useful_votes': False}}]:
        try:
            useful_votes(value)
        except VerificationFailure:
            rejected += 1
        else:
            raise VerificationFailure('missing_operator_vote_count_was_reconstructed')
    calls = []
    node = SimpleNamespace(argv=lambda args: ['unused-cli'] + args,
                           fixture_index=1, phase='self-test')
    result = SimpleNamespace(returncode=0, stdout=b'{"hits":[]}', stderr=b'')
    with mock.patch.object(subprocess, 'run', side_effect=lambda argv, **_: calls.append(argv) or result):
        for args in [['knowledge', 'search'], ['knowledge', 'search'],
                     ['knowledge', 'status'], ['info']]:
            FixtureNode.run(node, args)
    check(len(calls) == 4 and node.knowledge_cli_counts == {'search': 2, 'status': 1},
          'actual_knowledge_cli_counter_incorrect')
    with tempfile.TemporaryDirectory(prefix='idobata-public-binary-self-test-') as directory:
        binary = Path(directory) / 'candidate-idobata'
        binary.write_bytes(b'public native artifact fixture')
        local = SimpleNamespace(win=False, host=None, binary=str(binary))
        check(FixtureNode.binary_sha256(local) == hashlib.sha256(binary.read_bytes()).hexdigest(),
              'native_binary_digest_not_exact')
    upload_home = 'C:/Users/fixture/AppData/Local/Temp/idobata-fixture/node-test'
    uploaded = []
    upload = SimpleNamespace(win=True, host='fixture-host', home=upload_home,
                             fixture_index=1, phase='put', private_diagnostic=lambda _: None)
    for failure in ['exit', 'timeout']:
        def failed_upload(argv, **_):
            uploaded.append(Path(argv[-2]))
            if failure == 'timeout':
                raise subprocess.TimeoutExpired('fixture-sftp', 1)
            return SimpleNamespace(returncode=1, stdout=b'', stderr=b'')
        with mock.patch.object(subprocess, 'run', side_effect=failed_upload):
            try:
                FixtureNode.put(upload, upload_home + '/answer.json', b'fixture')
            except (VerificationFailure, subprocess.TimeoutExpired):
                pass
            else:
                raise VerificationFailure('failed_sftp_upload_was_accepted')
    check(len(uploaded) == 2 and all(not path.exists() for path in uploaded),
          'failed_sftp_upload_left_local_file')
    return {'rejected_inventory_or_vote_shapes': rejected,
            'placement_guard_cases': 2, 'cli_counter_cases': len(calls),
            'public_native_hash_cases': 1, 'sftp_failure_cleanup_cases': len(uploaded)}


def atomic_report(output, report):
    temporary = output.with_name(output.name + '.tmp-' + str(os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',
                        help='Same private JSON inventory as verify-peers.py; exactly four hosts')
    parser.add_argument('--output', help='Body-free JSON evidence output')
    parser.add_argument('--source-sha256',
                        help='Manager-verified source archive digest; not a CLI provenance proof')
    parser.add_argument('--self-test', action='store_true',
                        help='Run only independent solver vectors and malformed-input checks')
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps({'status': 'passed', 'test': 'automation-solver',
                          **solver_self_test()}), flush=True)
        return 0
    if not args.inventory or not args.output or not args.source_sha256:
        parser.error('--inventory, --output and --source-sha256 are required for real-host verification')
    if not ID_PATTERN.fullmatch(args.source_sha256):
        parser.error('--source-sha256 must contain exactly 64 lowercase hexadecimal characters')
    output = Path(args.output).resolve()
    if output.exists():
        parser.error('--output must be a new file; existing evidence is preserved')
    output.parent.mkdir(parents=True, exist_ok=True)
    run_id = str(time.time_ns())
    logs = output.parent / ('private-knowledge-logs-' + run_id)
    logs.mkdir(mode=0o700)
    report = {
        'version': 3,
        'test': 'real-host-one-operator-knowledge-e2e',
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'status': 'running',
        'checks': {},
        'retention_time_travel_tested': False,
        'production_services_changed': False,
        'automation_assurance_is_ai_identity': False,
        'source_archive_sha256': args.source_sha256,
        'source_provenance': 'manager_build_evidence_label_not_cli_attestation',
    }
    nodes = []
    tunnels = []
    binaries_verified = False
    stage = 'inventory'

    def record(name, result):
        report['checks'][name] = result
        atomic_report(output, report)
        print(json.dumps({'check': name, 'result': result}), flush=True)

    try:
        record('independent_automation_solver', solver_self_test())
        inventory = json.loads(Path(args.inventory).read_text())
        check(isinstance(inventory, list) and len(inventory) == 4, 'expected_four_hosts')
        for index, (config, port) in enumerate(zip(inventory, FIXTURE_PORTS)):
            fixture_config = fixture_node_config(config, index, port)
            nodes.append(FixtureNode(fixture_config, logs, run_id))
        check(sum(not node.host for node in nodes) == 1, 'expected_one_local_coordinator')
        first = next(node for node in nodes if not node.host)
        check(not first.win, 'local_coordinator_must_be_unix')
        hosts = [node.host for node in nodes if node.host]
        check(len(set(hosts)) == len(hosts), 'duplicate_fixture_ssh_alias')
        record('isolated_fixture_host_count', len(nodes))

        stage = 'native_artifact_hashes'
        supplied = sum(node.c.get('binary_sha256') is not None for node in nodes)
        record('expected_native_binary_hash_count', supplied)
        check(supplied == len(nodes), 'expected_native_binary_hashes_required')
        artifacts = []
        for index, node in enumerate(nodes):
            actual = node.binary_sha256()
            check(actual == node.c['binary_sha256'], 'native_binary_hash_mismatch')
            artifacts.append({'node_index': index + 1, 'platform': node.c['platform'],
                              'sha256': actual})
        binaries_verified = True
        record('verified_native_artifacts', artifacts)

        stage = 'sdk_versions'
        versions = []
        for node in nodes:
            result = subprocess.run(node.argv(['--version']), capture_output=True, timeout=30)
            check(result.returncode == 0, 'sdk_version_failed')
            version = result.stdout.decode('utf-8-sig').strip()
            check(version.startswith('idobata 0.3.'), 'new_sdk_required')
            versions.append(version)
        check(len(set(versions)) == 1, 'sdk_versions_differ')
        record('matching_native_sdk_count', len(versions))

        stage = 'initialize'
        identities = []
        for node in nodes:
            node.initialized = True
            value = node.run(['init', '--listen', f'/ip4/127.0.0.1/tcp/{node.port}'])
            identities.append(value['identity'])
        peer_ids = [identity['peer_id'] for identity in identities]
        check(len(set(peer_ids)) == 4, 'fixture_identities_not_distinct')
        for node, peer_id in zip(nodes, peer_ids):
            node.peer_id = peer_id
            node.member_keys = {identity['public_key']: identity['peer_id']
                                for identity in identities}
        profiles = parallel(lambda node: node.run(['profile']), nodes)
        check(all(profile == profiles[0] for profile in profiles), 'different_detector_artifacts')
        record('local_fixture_identity_count', len(peer_ids))
        record('identical_public_policy_and_wasm', True)

        stage = 'room_authorization'
        members_path = first.home + '/members.json'
        invite_path = first.home + '/invite.json'
        first.put(members_path, json.dumps(identities))
        operators_path = first.home + '/operators.json'
        first.put(operators_path, json.dumps({
            'bindings': {peer: 'fixture-shared-operator' for peer in peer_ids},
            'credits': {'fixture-shared-operator': 1000}}))
        created = first.run(['room', 'create', '--room', ROOM, '--members-file',
                             members_path, '--output', invite_path, '--require-automation',
                             '--operators-file', operators_path])
        authority = created['authority_peer_id']
        invite = Path(invite_path).read_bytes()
        certificate = json.loads(invite)
        check(certificate['signed'].get('knowledge_automation_required') is True
              and certificate['signed'].get('version') == 4
              and certificate['signed'].get('knowledge_operators', {}).get('bindings')
              == {peer: 'fixture-shared-operator' for peer in peer_ids},
              'room_did_not_require_automation')
        for node in nodes:
            node.room_id = certificate['signed']['room_id']
            node.authority = authority
            if node is first:
                continue
            node.put(node.home + '/invite.json', invite)
            node.run(['room', 'join', '--room', ROOM, '--invite-file',
                      node.home + '/invite.json', '--trust-authority', authority])
        record('fixed_authorized_roster_size', len(nodes))
        record('operator_trust_assumption', {'physical_host_count': len(nodes),
               'actual_operator_count': 1, 'registered_operator_count': 1,
               'independence_is_authority_attested': True,
               'synthetic_independent_operators_on_real_hosts': False})

        stage = 'fixture_transport'
        for node in nodes:
            if not node.host:
                continue
            forward = HELPERS.SSH + [
                '-N', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15',
                '-L', f'127.0.0.1:{node.port}:127.0.0.1:{node.port}',
            ]
            for other in nodes:
                if other is not node:
                    forward += ['-R', f'127.0.0.1:{other.port}:127.0.0.1:{other.port}']
            forward.append(node.host)
            tunnels.append(subprocess.Popen(forward, stdin=subprocess.DEVNULL,
                                            stdout=node.log, stderr=node.log))
        time.sleep(1)
        check(all(tunnel.poll() is None for tunnel in tunnels), 'fixture_forward_failed')
        parallel(lambda node: node.start(), nodes)
        record('ready_daemon_count', len(nodes))
        stage = 'initial_peer_readiness'
        ready_counts = wait_peer_readiness(nodes)
        record('authenticated_ready_host_count', len(ready_counts))
        for node in nodes:
            information = node.run(['info'])
            expirations = information.get('knowledge', {}).get('expired_background_requests')
            check(type(expirations) is int and expirations >= 0,
                  'candidate_missing_background_timeout_capability')
            marker = information.get('knowledge', {}).get('operator_policy_version')
            check(type(marker) is int and marker == 1,
                  'candidate_missing_operator_policy_capability')
            rooms = information.get('rooms', [])
            check(any(room.get('name') == ROOM
                      and room.get('authorized') is True
                      and room.get('knowledge_automation_required') is True for room in rooms),
                  'daemon_room_did_not_require_automation')
        record('automation_required_room_host_count', len(nodes))
        record('background_timeout_capability_host_count', len(nodes))
        record('operator_policy_capability_host_count', len(nodes))

        stage = 'blocked_inputs'
        for node in nodes:
            before = status(node)
            blocked_input = {'problem': '検査用の合成値を送らない',
                             'solution': HELPERS.SYNTHETIC, 'context': '',
                             'references': [], 'kind': 'answer'}
            blocked_post = node.mutation_request(
                ['knowledge', 'publish', '--room', ROOM, '--stdin'], blocked_input, codes=(20,))
            blocked_search = node.run(['knowledge', 'search', '--room', ROOM,
                                      '--query', HELPERS.SYNTHETIC, '--limit', '10'], codes=(20,))
            check(HELPERS.SYNTHETIC not in json.dumps([blocked_post, blocked_search]),
                  'blocked_diagnostic_disclosed_input')
            check('challenge' not in blocked_post, 'blocked_input_created_automation_challenge')
            after = status(node)
            check(before['objects'] == after['objects'] == 0,
                  'blocked_publish_created_record')
            for name in ('outbound_attempts', 'network_requests'):
                if name in before and name in after:
                    check(before[name] == after[name], 'blocked_input_caused_network_request')
        record('blocked_publish_and_search_count', len(nodes) * 2)

        stage = 'publish'
        fixtures = []
        labels = ['一番目', '二番目', '三番目', '四番目']
        for round_index in range(2):
            inputs = []
            for index, node in enumerate(nodes):
                body = {
                    'problem': f'知識検証 {labels[index]}のノード {round_index + 1}件目 固有事例{index + 1}番{round_index + 1}回 同じ依頼が重複して実行される',
                    'solution': '依頼の番号と処理結果を保存し、同じ番号では保存した結果を返す。',
                    'context': '処理結果と依頼の番号を同時に保存できる場合に使う。',
                    'references': [],
                    'kind': 'answer' if round_index == 0 else 'hint',
                }
                inputs.append((index, node, body))

            def publish(item):
                index, node, body = item
                value = node.mutate(['knowledge', 'publish', '--room', ROOM, '--stdin'], body)
                record_id = value.get('id', '')
                check(ID_PATTERN.fullmatch(record_id), 'publish_missing_id')
                check(value.get('stored') is True, 'publish_not_stored')
                check(value.get('replication_factor') == 3, 'publish_wrong_replication_factor')
                return {'id': record_id, 'author': peer_ids[index],
                        'author_index': index, 'input': body,
                        'unique_query': f'固有事例{index + 1}番{round_index + 1}回'}

            fixtures.extend(parallel(publish, inputs))
        check(len({fixture['id'] for fixture in fixtures}) == 8, 'publish_duplicate_id')
        record('published_record_count', len(fixtures))
        record('certified_publish_count', sum(node.automation_counts['publish'] for node in nodes))

        stage = 'three_replica_handoff'
        began = time.monotonic()
        snapshots = wait_replicas(nodes, fixtures, peer_ids)
        copies = record_inventory(snapshots)
        handoffs = require_nonkeeper_authors(fixtures, copies)
        record('converged_replication', {
            'record_count': len(fixtures),
            'persistent_copy_count': sum(len(items) for items in copies.values()),
            'minimum_copies_per_record': min(map(len, copies.values())),
            'maximum_copies_per_record': max(map(len, copies.values())),
            'staging_record_count': sum(record['staging'] for value in snapshots
                                        for record in value['records']),
            'nonkeeper_author_handoff_count': len(handoffs),
            'wait_seconds': round(time.monotonic() - began, 3),
        })

        stage = 'normal_and_explicit_exploration'
        wait_peer_readiness(nodes)
        normal = parallel(lambda node: search(node, explore=False), nodes)
        check(all(value['hits'] == [] and value.get('partial') is False
                  and value.get('reason') == 'insufficient_independent_operators'
                  and value.get('exploration_available') is True
                  and type(value.get('responded_peers')) is int
                  and value['responded_peers'] >= 1 for value in normal),
              'one_operator_normal_exposed_unconfirmed')
        explored = parallel(search, nodes)
        check(all(len(value['hits']) == 1 and value.get('partial') is False
                  and value.get('search_mode') == 'explore'
                  and value['hits'][0].get('confirmation') == 'unconfirmed'
                  and value['hits'][0].get('author_peer_id') in peer_ids
                  and value['hits'][0].get('untrusted') is True
                  and type(value.get('responded_peers')) is int
                  and value['responded_peers'] >= 1
                  for value in explored), 'one_operator_explore_limit_failed')
        record('normal_unconfirmed_result_count', sum(len(value['hits']) for value in normal))
        record('generic_explore_maximum_hits_per_host', max(len(value['hits']) for value in explored))
        individual_queries = 0
        for fixture in fixtures:
            deadline = time.monotonic() + WAIT_SECONDS
            while True:
                searches = parallel(lambda node: search(node, fixture['unique_query']), nodes)
                individual_queries += len(searches)
                if all(len(value['hits']) == 1
                       and value['hits'][0]['id'] == fixture['id']
                       and value['hits'][0].get('author_peer_id') == fixture['author']
                       and value.get('partial') is False
                       and type(value.get('responded_peers')) is int
                       and value['responded_peers'] >= 1 for value in searches):
                    break
                check(time.monotonic() < deadline, 'individual_exploration_deadline')
                time.sleep(1)
            for value in searches:
                check(all(hit.get('untrusted') is True for hit in value['hits']),
                      'missing_untrusted_search_marker')
            # Four simultaneous searches send three requests to each peer.
            # Leave room under the shared operator rate for replication work.
            time.sleep(1)
        record('individual_japanese_exploration', {'record_count': len(fixtures),
               'host_record_matches': len(fixtures) * len(nodes),
               'actual_query_invocations': individual_queries})

        stage = 'nonholder_network_get'
        for fixture in fixtures:
            holders = {index for index, _ in copies[fixture['id']]}
            nonholder = next(index for index in range(4) if index not in holders)
            check(verified_get(nodes[nonholder], fixture) is not None,
                  'nonholder_network_get_failed')
        snapshots = wait_replicas(nodes, fixtures, peer_ids)
        record('nonholder_verified_get_count', len(fixtures))
        record('nonholder_reads_preserved_replica_cap', True)

        stage = 'signed_useful_feedback'
        wait_peer_readiness(nodes)
        targets = [fixture for fixture in fixtures if fixture['author_index'] == 0]
        for target in targets:
            def evaluate(node):
                return node.mutate(
                    ['knowledge', 'evaluate', '--room', ROOM, '--id', target['id'], '--stdin'],
                    {'verdict': 'useful',
                     'evidence': '同じ番号の依頼を再送する試験で、処理を重複せず保存した結果を返した。',
                     'references': []})
            parallel(evaluate, nodes[1:3])
        deadline = time.monotonic() + WAIT_SECONDS
        while True:
            values = [verified_get(nodes[3], target) for target in targets]
            if all(value is not None and useful_votes(value) == 0
                   and len(value.get('reviews', [])) == 2
                   and {review.get('reviewer_peer_id') for review in value['reviews']}
                   == set(peer_ids[1:3])
                   and value.get('quality', {}).get('author_reputation') == 0.5
                   and value.get('confirmation') == 'unconfirmed' for value in values):
                break
            check(time.monotonic() < deadline, 'useful_feedback_deadline')
            time.sleep(1)
        record('distinct_other_peer_evaluation_count', len(targets) * 2)
        record('certified_evaluation_count', sum(node.automation_counts['evaluate'] for node in nodes))
        record('automation_admission', {
            'challenge_before_storage_count': sum(sum(node.automation_counts.values()) for node in nodes),
            'successful_proof_resubmission_count': sum(sum(node.automation_counts.values()) for node in nodes),
            'machine_case_answers_checked': AUTOMATION_CASES * sum(
                sum(node.automation_counts.values()) for node in nodes),
            'assurance': 'automation_tested',
        })
        peers = nodes[3].run(['knowledge', 'peers', '--room', ROOM,
                              '--query', QUERY, '--limit', '10', '--explore'])
        peer_results = peers.get('peers')
        check(isinstance(peer_results, list) and len(peer_results) == 1
              and peers.get('partial') is False
              and peers.get('search_mode') == 'explore'
              and type(peers.get('responded_peers')) is int and peers['responded_peers'] >= 1
              and peer_results[0].get('peer_id') in peer_ids
              and peer_results[0].get('untrusted') is True,
              'same_operator_peer_exposure_exceeded')
        target = targets[0]
        individual_peers = nodes[3].run(['knowledge', 'peers', '--room', ROOM,
                                       '--query', target['unique_query'], '--limit', '10', '--explore'])
        discovered = individual_peers.get('peers')
        check(isinstance(discovered, list) and len(discovered) == 1
              and discovered[0].get('peer_id') == target['author']
              and discovered[0].get('record_ids') == [target['id']]
              and discovered[0].get('matching_records') == 1
              and discovered[0].get('untrusted') is True
              and individual_peers.get('partial') is False
              and type(individual_peers.get('responded_peers')) is int
              and individual_peers['responded_peers'] >= 1,
              'individual_exploration_did_not_discover_author')
        normal_after = parallel(lambda node: search(node, explore=False), nodes)
        check(all(value['hits'] == [] and value.get('partial') is False
                  and type(value.get('responded_peers')) is int
                  and value['responded_peers'] >= 1 for value in normal_after),
              'same_operator_votes_promoted_record')
        record('same_operator_endorsements', {'physical_review_packets': len(targets) * 2,
               'independent_useful_votes': 0, 'author_prior': 0.5,
               'normal_results_after_endorsement': 0,
               'maximum_explored_peer_count': len(peer_results)})
        record('individual_query_discovered_expected_author', True)

        stage = 'restart_persistence'
        snapshots = wait_replicas(nodes, fixtures, peer_ids)
        before_ids = [{item['id'] for item in value['records']} for value in snapshots]
        for index, node in enumerate(nodes):
            node.stop()
            node.start()
            wait_peer_readiness(nodes)
            restored = status(node)
            check({item['id'] for item in restored['records']} == before_ids[index],
                  'restart_lost_persistent_knowledge')
        snapshots = wait_replicas(nodes, fixtures, peer_ids)
        record('restart_preserved_knowledge_host_count', len(nodes))

        stage = 'encrypted_knowledge_store'
        for index, node in enumerate(nodes):
            held = next(fixture for fixture in fixtures if fixture['id'] in before_ids[index])
            check(node.knowledge_encrypted(held['input']['problem']),
                  'knowledge_store_plaintext_or_missing')
        record('encrypted_knowledge_store_host_count', len(nodes))

        stage = 'author_offline_retrieval'
        copies = record_inventory(snapshots)
        selected = require_nonkeeper_authors(fixtures, copies)[0]
        author_index = selected['author_index']
        nodes[author_index].stop()
        remaining = [node for index, node in enumerate(nodes) if index != author_index]
        wait_peer_readiness(remaining)
        results = parallel(lambda node: verified_get(node, selected), remaining)
        check(all(value is not None for value in results), 'author_offline_get_failed')
        offline_searches = parallel(lambda node: search(node, selected['unique_query']), remaining)
        check(all(value.get('partial') is True for value in offline_searches),
              'offline_search_not_marked_partial')
        check(all(type(value.get('responded_peers')) is int
                  and value['responded_peers'] >= 1 for value in offline_searches),
              'offline_search_had_no_live_peer_response')
        check(all(any(hit['id'] == selected['id'] for hit in value['hits'])
                  for value in offline_searches), 'author_offline_search_lost_record')
        live_holders = sum(index != author_index for index, _ in copies[selected['id']])
        check(live_holders == 3, 'author_offline_requires_three_live_keepers')
        record('author_offline_retrieval', {
            'responding_host_count': len(results),
            'live_keeper_count': live_holders,
            'original_author_preserved': True,
            'offline_search_marked_partial_count': len(offline_searches),
        })
        report['status'] = 'passed'
    except (Exception, KeyboardInterrupt) as error:
        report['status'] = 'failed'
        report['failed_stage'] = stage
        # Exception strings can contain rejected input, paths or remote output.
        # Preserve only a public classification and the static stage name.
        report['failure_type'] = type(error).__name__
        if isinstance(error, VerificationFailure):
            report['failure_code'] = str(error)
            if str(error) == 'fixture_placement_insufficient':
                report['failure_class'] = 'fixture_placement_not_product_replication_failure'
            if hasattr(error, 'replication_diagnostics'):
                report['replication_diagnostics'] = error.replication_diagnostics
            if error.node_index is not None:
                report['failure_node_index'] = error.node_index
            if error.phase is not None:
                report['failure_phase'] = error.phase
        print(json.dumps({'status': 'failed', 'stage': stage,
                          'failure_type': type(error).__name__}), flush=True)
    finally:
        if binaries_verified:
            verified_after = 0
            failures = []
            for index, node in enumerate(nodes):
                try:
                    check(node.binary_sha256() == node.c['binary_sha256'],
                          'native_binary_changed_during_fixture')
                    verified_after += 1
                except Exception:
                    failures.append({'node_index': index + 1,
                                     'operation': 'verify_native_binary_unchanged'})
            report['checks']['native_binary_unchanged_after_fixture'] = {
                'verified_host_count': verified_after, 'expected_host_count': len(nodes)}
            report['native_artifact_postcheck_errors'] = failures
            if failures:
                report['status'] = 'failed'
        cleanup_errors = []
        stopped = []
        for index, node in reversed(list(enumerate(nodes))):
            try:
                node.stop()
                stopped.append(node)
            except Exception:
                cleanup_errors.append({'node_index': index + 1, 'operation': 'stop'})
        for tunnel in tunnels:
            try:
                tunnel.terminate()
                try:
                    tunnel.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    tunnel.kill()
                    tunnel.wait(timeout=5)
            except Exception:
                cleanup_errors.append({'operation': 'tunnel_stop'})
        removed = 0
        for node in stopped:
            try:
                node.remove_data()
                if node.initialized:
                    removed += 1
            except Exception:
                cleanup_errors.append({'node_index': nodes.index(node) + 1,
                                       'operation': 'remove_fixture_data'})
        for node in nodes:
            node.log.close()
        report['actual_knowledge_cli_invocations'] = {
            purpose: sum(getattr(node, 'knowledge_cli_counts', {}).get(purpose, 0) for node in nodes)
            for purpose in ('publish', 'evaluate', 'search', 'get', 'peers', 'status')}
        report['cleanup_error_count'] = len(cleanup_errors)
        report['cleanup_errors'] = cleanup_errors
        report['private_fixture_keys_removed'] = not cleanup_errors
        report['fixture_data_directory_removed_count'] = removed
        if cleanup_errors:
            report['status'] = 'failed'
        report['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        atomic_report(output, report)
    print(json.dumps({'status': report['status'], 'check_count': len(report['checks']),
                      'cleanup_error_count': report['cleanup_error_count']}), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
