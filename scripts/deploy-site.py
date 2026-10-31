#!/usr/bin/env python3
"""既存frontdoorへ静的サイトだけを追加する。新規Pod・PVC・LBを作らない。"""
import argparse
import base64
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BEGIN = '# BEGIN IDOBATA SITE'
END = '# END IDOBATA SITE'
FILES = {
    'idobata-index.html': 'site/index.html',
    'idobata-docs.html': 'site/docs/index.html',
    'idobata-style.css': 'site/style.css',
    'idobata-app.js': 'site/app.js',
    'idobata-posts.json': 'site/posts.json',
    'idobata-publisher.json': 'site/publisher.json',
    'idobata-sitemap.xml': 'site/sitemap.xml',
}


def run(args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          check=True, timeout=60).stdout


def replace_block(config, fragment):
    if config.count(BEGIN) != config.count(END) or config.count(BEGIN) > 1:
        raise ValueError('idobata設定の境界が不正です')
    if BEGIN in config:
        start = config.index(BEGIN)
        finish = config.index(END, start) + len(END)
        return config[:start] + fragment.rstrip() + config[finish:]
    if 'server_name idobata.s21g.com' in config:
        raise ValueError('管理外のidobata設定があります')
    offset = config.rfind('}')
    if offset < 0 or config[offset + 1:].strip():
        raise ValueError('httpブロックの末尾を確認できません')
    return config[:offset] + fragment + '\n' + config[offset:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--namespace', default='default')
    parser.add_argument('--configmap', default='moon-frontdoor-config')
    parser.add_argument('--selector', default='app=frontdoor')
    parser.add_argument('--binary', default=str(ROOT / 'target/debug/idobata'))
    parser.add_argument('--apply', action='store_true', help='検証後に適用する')
    parser.add_argument('--remove', action='store_true', help='自サイトの設定とファイルだけを撤去')
    args = parser.parse_args()
    k = ['kubectl', '--context', args.context, '-n', args.namespace]
    cm = json.loads(run(k + ['get', 'configmap', args.configmap, '-o', 'json']))
    original = cm['data']['nginx.conf']
    fragment = '' if args.remove else (ROOT / 'site/nginx.conf').read_text()
    rendered = replace_block(original, fragment)
    text = {} if args.remove else {
        key: (ROOT / path).read_text() for key, path in FILES.items()
    }
    icon_key = 'idobata-icon.png'
    icon = b'' if args.remove else (ROOT / 'assets/icons/idobata-icon.png').read_bytes()
    if not args.remove:
        # フィード内の鍵を信頼しない。別ファイルで固定した公開鍵で検証する。
        run([args.binary, 'public', 'verify', '--feed', str(ROOT / 'site/posts.json'),
             '--trust-publisher', str(ROOT / 'site/publisher.json')])
    old_binary = cm.get('binaryData', {})
    total = sum(len(v.encode()) for key, v in cm['data'].items()
                if key not in FILES and key != 'nginx.conf')
    total += sum(len(base64.b64decode(v)) for key, v in old_binary.items()
                 if key != icon_key)
    total += len(rendered.encode()) + sum(len(v.encode()) for v in text.values()) + len(icon)
    if total >= 1024 * 1024:
        raise ValueError('ConfigMapの容量を超えるため配備を中止しました')
    pods = json.loads(run(k + ['get', 'pods', '-l', args.selector, '-o', 'json']))['items']
    ready = [p['metadata']['name'] for p in pods
             if any(c['type'] == 'Ready' and c['status'] == 'True'
                    for c in p.get('status', {}).get('conditions', []))]
    if not ready:
        raise ValueError('検証可能な稼働frontdoorがありません')
    for pod in ready:
        # 設定テストだけを行う。既存masterへシグナルを送らない。
        run(k + ['exec', '-i', pod, '-c', 'nginx', '--', 'sh', '-c',
                 'umask 077; f=$(mktemp /tmp/idobata-nginx.XXXXXX); '
                 'trap \'rm -f "$f"\' EXIT; cat > "$f"; nginx -t -c "$f"'], rendered)
    print(json.dumps({'status': 'validated', 'config_bytes': total,
                      'frontdoors': len(ready), 'apply': args.apply}))
    if not args.apply:
        return
    patch = [
        {'op': 'test', 'path': '/metadata/resourceVersion',
         'value': cm['metadata']['resourceVersion']},
        {'op': 'replace', 'path': '/data/nginx.conf', 'value': rendered},
    ]
    if args.remove:
        for key in FILES:
            if key in cm['data']:
                patch.append({'op': 'remove', 'path': '/data/' + key})
        if icon_key in old_binary:
            patch.append({'op': 'remove', 'path': '/binaryData/' + icon_key})
    else:
        patch.extend({'op': 'add', 'path': '/data/' + key, 'value': value}
                     for key, value in text.items())
        if 'binaryData' not in cm:
            patch.append({'op': 'add', 'path': '/binaryData', 'value': {}})
        patch.append({'op': 'add', 'path': '/binaryData/' + icon_key,
                      'value': base64.b64encode(icon).decode()})
    # パッチはstdinで渡す。OSの引数上限・シェル展開を避ける。
    run(k + ['patch', 'configmap', args.configmap, '--type=json',
             '--patch-file=/dev/stdin'], json.dumps(patch))
    print(json.dumps({'status': 'applied', 'reload': 'existing-frontdoor-reloader'}))


if __name__ == '__main__':
    main()
