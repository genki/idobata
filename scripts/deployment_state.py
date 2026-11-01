"""導入時に既存の鍵・署名journal・残高状態を上書きしない境界。"""
import os
from pathlib import PurePosixPath

# Coreのcheckpoint・pending・submission trackingもapplication.enc内にある。
MUTABLE_FILES = (
    'config.json', 'state.enc', 'knowledge.enc', 'automation-nonces.json',
    'public-projection.enc', 'ledger-settings.json', 'ledger-consensus.enc',
    'ledger-minimum.enc', 'ledger-application.enc', 'ledger-consensus.initialized',
    'trust-root.json', 'trust.json',
)
IMMUTABLE_FILES = ('identity.key', 'storage.key')
LOCK_FILES = ('config.lock', 'daemon.lock', 'ledger-consensus.lock')


def assert_bootstrap_fresh(home, binary, service_paths=(), service_present=False):
    """存在だけを調べる。秘密鍵・mutable fileの値やhashを読まない。"""
    if (service_present or any(os.path.lexists(path)
                              for path in [home, binary, *service_paths])):
        raise RuntimeError('existing_installation_requires_guarded_upgrade')


def unchanged_for_binary_rollback(before, after):
    """停止中checkpointの全inventoryが一致するときだけ旧SDK候補を許す。

    stateを戻す関数ではない。counter/minimum/WALが一つでも変わればFalse。
    鍵は内容比較へ入れず、既存upgrade helperの所有者・ACL検証を維持する。
    """
    return (isinstance(before, dict) and isinstance(after, dict)
            and set(before) == set(MUTABLE_FILES) == set(after)
            and before == after)


def assert_cli_targets(platform, targets):
    """CLI-only installerの書込先をSDK/dataから切り離す。"""
    if platform == 'windows':
        allowed = {'c:/program files/idobata/bin/idobata.exe',
                   'c:/program files/idobata/bin/idobata.new.exe',
                   'c:/program files/idobata/agent.socket'}
        normalized = [str(value).replace('\\', '/').lower() for value in targets]
    elif platform in ['linux', 'macos']:
        allowed = {'/usr/local/bin/idobata', '/usr/local/bin/idobata.new'}
        normalized = [str(value) for value in targets]
    else:
        raise ValueError('unsupported_cli_platform')
    if not normalized or any('..' in PurePosixPath(value).parts
                             or value not in allowed for value in normalized):
        raise ValueError('cli_target_outside_launcher_scope')
    return True
