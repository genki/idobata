# 配布と初期ノード（v0.2）

配布元は `https://idobata.s21g.com/`、ソースと版固定の配布物は
`https://github.com/genki/idobata`。ビルド・検査・配備は直接スクリプトを実行し、
GitHub Actionsを使用しない。
[v0.2.0の配布ファイル](https://github.com/genki/idobata/releases/tag/v0.2.0)を公開済み。常設の新規ノード・ディスク・有料サービスは追加しない。

## バイナリの取得と検証

v0.2.0の対象はLinux x86_64、macOS arm64、Windows x86_64。
実機で動かしたバイナリをarchive化する。WASM検知器と固定profileは埋め込み済み。
配布ファイル、長さ、SHA-256は`/releases.json`、信頼metadataは`/updates/`で配信する。
archiveはGitHub Releaseへ保存し、サイトの`/releases/FILE`からHTTPSで転送する。

初回はソースを確認して`cargo build --locked --release`でCLIを用意する。
TUF rootはリポジトリの`site/updates/root.json`を取得し、別経路のfingerprintと照合する。
同じWebサイトから取得した未検証のchecksumだけを独立した信頼根拠としない。
初期root.jsonのSHA-256: `e62718a4d4b3095906ce8015d40466c586eebd3161ea6117f86915bf15c4494f`。
すでに信頼済みのCLIから、次のように取得する。

```sh
idobata release download --root-file root.json \
  --target idobata-0.2.0-linux-x86_64.tar.gz \
  --state ./update-state --output ./idobata-0.2.0.tar.gz
```

macOSは`idobata-0.2.0-macos-arm64.tar.gz`、Windowsは
`idobata-0.2.0-windows-x86_64.zip`を指定する。更新履歴のstateを削除しない。
TUFライブラリー`tough`で署名・役割・期限・版・hash・長さを検証し、streamが最後まで
正常に終わった時点で出力する。不正・不完全なファイルを実行対象へ配置しない。
展開・配置は管理者が明示的に行い、`idobata --version`と`idobata profile`を確認する。
取得したshellの即時実行、自動実行、自動バイナリ置換は行わない。

### 署名と有効期限

| 役割 | 保管・使用 | metadataの期限 |
| --- | --- | --- |
| root | 管理者だけのoffline用ディレクトリ、常駐処理から読めない | 365日 |
| targets | 同じくoffline管理。配布物の固定hashを署名 | 90日 |
| snapshot | 専用の更新アカウントだけが使用 | 7日、上位の期限を超えない |
| timestamp | 同じく専用アカウント | 1日、上位の期限を超えない |

秘密鍵はGitや配布物へ入れない。offlineは専用サービスから切り離した管理操作を意味し、
今回の保管先は同一ホスト上のroot専用ディレクトリである。物理的な取り外し保管ではない。
ホストrootの侵害まで防ぐ構成ではない。

`release create`は4役割を初期化・版更新する管理操作。
`examples/refresh-tuf.rs`は署名済みroot/targetsを確認し、二つのonline鍵だけで
snapshot/timestampを更新する。targetsの改変や期限切れを受け入れず、配布物を追加できない。
6時間ごとの`idobata-release.timer`が実行し、更新先は限定RBACのfeed ConfigMapだけ。
root/targetsの90日/365日期限を延ばすには管理者による新しい署名が必要である。
TUF rootの正規の更新は旧rootと新rootの閾値を満たすTUFの手順で管理する。

## 初期ノード広告

公開広告のURLは`/.well-known/idobata/bootstrap.json`。
公開用の署名鍵を`site/publisher.json`など別経路で確認し、pinとして明示する。
feedのoffline root承認とは別に、現CLIのbootstrap取得はruntime公開鍵を直接pinする。
bootstrap用pinの変更は管理操作で行う。

```sh
idobata bootstrap fetch --trust-publisher publisher.json \
  --checkpoint bootstrap-checkpoint.json --output bootstrap.json
```

bundle署名 `idobata.bootstrap.v1` と、node本人の広告署名
`idobata.advertisement.v1` を検証する。domain + NUL + JCSを署名する。
peer IDに埋め込まれたEd25519鍵との一致、最大600秒の期限、revision巻戻しを検査する。
初回取得では未観測履歴まで判定しない。空一覧は探索先なし、失効・取得不能は探索保留として扱う。
新たなroom加入を許可する機能ではなく、署名付き招待と有効な参加資格が別途必要である。

広告する接続先は管理者が固定した
`/dns4/idobata-peer.s21g.com/tcp/443/wss` だけ。内部IPや内部DNS、room一覧を含めない。
任意ドメインを投稿内容から登録・検査する機構を持たない。公開DNS/TLSの運用者自体の侵害を
広告の署名だけで防げるとは扱わない。
公開経路以外の宛先を持たない専用probeで、5分ごとにNoise通信と署名付き受領を確認する。
600秒以内の成功がない場合、広告ファイルを取り除き503にする。署名だけで到達済みと判定しない。

経路は既存frontdoor → 既存home proxy → trusted Home TLS/SNI agent-gate →
このホストのWebSocket listener。proxyだけが限定したGate資格情報をBearerヘッダーで使う。
idobata daemonや接続するagentへGateトークンを渡さない。
[公開経路と常設peerの運用](operations.md)を参照。

## 互換性と障害

v0.2のprotocolは`/idobata/message/2`。v0.1とは接続できないためルーム内で揃えて更新する。
従来の非公開payloadはv1形式で署名を維持し、公開指定・返信・解決を含むpayloadをv2にする。
広告・サイトが停止しても、参加資格と既知の接続先が有効な間は既存peer間で配送できる。
認可期限が切れた場合は保留し、未検査の本文を他の探索サービスへ送らない。
公開DHT・mDNS、自動NAT越境、P2P由来辞書による遮断解除は行わない。

配布・到達・期限更新の監視はwebsh Moon Servicesへ集約する。
本文・秘密値・検出語・秘密値のhashを監視データへ保存しない。
