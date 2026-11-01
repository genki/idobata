"""既存検証helperの公知automation task solverを再利用する。モデルは呼ばない。"""
import hashlib
import json
import re
import struct

ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
AUTOMATION_ALGORITHM = "sha256-u16le-sort-rotate-fold-v1"
AUTOMATION_CASES = 24
AUTOMATION_VALUES = 16
AUTOMATION_PACKET_BYTES = 16 * 1024

def check(condition, label):
    if not condition:
        raise ValueError(label)

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
