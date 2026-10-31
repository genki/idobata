# 配布と初期ノード

配布元は `https://idobata.s21g.com/`、ソースと版固定の配布物は
`https://github.com/genki/idobata`。ビルド・検査・配備は直接スクリプトを実行し、
GitHub Actionsを使用しない。
[v0.2.0の配布ファイル](https://github.com/genki/idobata/releases/tag/v0.2.0)を公開済み。常設の新規ノード・ディスク・有料サービスは追加しない。

## crates.ioからCLIを導入する（公開待ち）

Rustの公式レジストリは[crates.io](https://crates.io/)を使う。
v0.3.0の`idobata`と`idobata-scanner`は公開準備中であり、現時点で公開済みとはしない。
2026-11-01の公式API確認では両名とも404だった。これは名前の予約や今後の取得を保証しない。
確認対象4ホストでCargoの読取操作`cargo owner --list --registry crates-io idobata`を実行し、
通常のCargo設定ではtokenが見つからなかった。その後、保護された既存資格情報を公開用の子Cargoへ
限定して渡し、既存crateの所有者一覧取得に成功した。実公開で必要な権限は公開時の結果で確認する。
tokenの新規発行や`cargo login`による永続保存は行っていない。
2026-11-01にCargo 1.96で`cargo package --workspace --locked --allow-dirty`と
`cargo publish --dry-run --workspace --locked --allow-dirty --registry crates-io`が成功した。
追加された自動処理テストを含む固定ソースでも、両packageの展開後buildと公開dry-runが成功した。
[最終package検査の記録](../evidence/cargo-package-v03-20261101.json)に、file数・SHA・ログのhash・
同梱物の確認を残した。実公開・crates.ioからのinstallは別に確認する。

公開後はRust 1.88以降とネイティブのビルド環境を用意し、次を実行する。

```sh
cargo install idobata --locked
idobata --version
```

版を固定する場合は`cargo install idobata --version 0.3.0 --locked`を使う。
Cargoは既定でcrates.ioから取得し、`--locked`で配布物に含まれる`Cargo.lock`を使う。
[Cargo公式の導入仕様](https://doc.rust-lang.org/cargo/commands/cargo-install.html)を参照。
WindowsではRustのMSVC向けビルド環境、macOSではCommand Line Tools等が別途必要となる。
WASM検知器は埋め込み済みなので、導入時にWASM targetや検知器の再生成は不要。

この操作はCLIを利用者のCargoのbinディレクトリへ置く。デーモンのサービス登録、roomへの参加、
管理者用ディレクトリの作成を自動実行しない。既存の認可済みデーモンを使うagentは、
鍵や管理者権限を受け取らず、既存の共有IPCを利用する。

```sh
idobata --socket ENDPOINT knowledge status --room engineering
```

接続先は資格情報ではなく、OSのUID/SIDで利用を認可する。
`--socket`を明示した場合はそれを優先し、ローカル設定があればその設定を使う。
ローカル設定がなければ、SDK自身がOSごとの既存共有IPCを選ぶ。
明示した`--home`の設定が無い・読めない場合は、共有IPCへ黙って切り替えない。
native launcherも既存の接続先を補完するが、cargo版の利用に別のlauncherは必須としない。

## crates.ioへ公開する手順

配布単位は次の2つとする。

| パッケージ | 内容 | 公開順 |
| --- | --- | --- |
| `idobata-scanner` | 固定profileとネイティブ検査器のRustライブラリー | 先 |
| `idobata` | CLI・デーモン、署名・保存・P2P通信、固定WASM | 後 |

SDKの依存にはpathと`version = "=0.3.0"`を併記する。公開用manifestからpathが除かれ、
レジストリの同じ版のscannerを参照する。SDK内の`assets/scanner.wasm`は、
`crates/scanner/artifacts/scanner.wasm`とbyte単位で同じものを同梱する。
現在の固定WASMのSHA-256は
`e765bdca9f335bed3c26c2dee1bce39e9eb652e2af2552945c1818934d88e4fd`。
配布の都合でWASMを再生成したり、検知profileを変更したりしない。

両パッケージのincludeを明示し、Rustソース、例・テスト、READMEとCargo.lockを含める。
SDKに必要なWASMはSDK自身のpackage内に置き、隣のscannerディレクトリを参照しない。
鍵、招待、nodeデータ、運用inventory、サイトの状態を含めない。
[Cargo公式のpackaging仕様](https://doc.rust-lang.org/cargo/commands/cargo-package.html)に従う。

公開前にファイル一覧と、展開したpackageからのビルドを確認する。
公開検査ではCargo 1.96のworkspace packagingを使い、未公開のscannerを一時レジストリへ置いて
依存関係を検査できる。利用者の`cargo install`がこの一時レジストリを使うわけではない。

```sh
cargo package --list --locked -p idobata-scanner
cargo package --list --locked -p idobata
cargo package --workspace --locked
cargo publish --dry-run --workspace --locked --registry crates-io
```

作業中の変更を検査する場合だけ`--allow-dirty`を明示する。これは未commitの状態を公開可能にする
例外であり、最終配布のソース一致確認を代替しない。
プロジェクトのライセンスはMITとする。rootの`LICENSE`を正本とし、両crateに同じ全文を含め、
normalized manifestにも`license = "MIT"`を記録する。ネイティブarchiveにも正本を同梱する。
dry-runの成功は、レジストリの認証や
アップロード後のサーバー検査が完了したことを意味しない。

認証を設定できたら、scannerを先に公開し、公式indexへ0.3.0が現れたことを確認する。
続けてSDKのdry-runを再実行し、公開されたscannerのchecksumを使うロックファイルで検査してから公開する。
公開操作は次の順序となる。

```sh
cargo publish --locked -p idobata-scanner --registry crates-io
cargo publish --dry-run --locked -p idobata --registry crates-io
cargo publish --locked -p idobata --registry crates-io
```

認証には既存の保護された資格情報またはCargo credential providerを使う。
dotenvの指定キーを使う場合は実行可能なshellとしてsourceせず、データとして解釈し、
公開用の子プロセスの`CARGO_REGISTRY_TOKEN`にだけ渡す。
tokenを引数、ログ、証跡、リポジトリや新しい永続設定へ書かない。
公開後に空のinstall rootから`cargo install idobata --version 0.3.0 --locked`を実行し、
version、profileと基本CLIを確認して初めて導入経路を検証済みとする。
一度公開した版は上書きできないため、試験目的の実公開はしない。
[Cargo公式の公開手順](https://doc.rust-lang.org/cargo/reference/publishing.html)を参照。

## バイナリの取得と検証（公開済みv0.2）

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

v0.3の自動処理テスト必須roomは、署名付きのversion 3招待を使う。
既存4ホストでは、先に全SDKを0.3へ更新して正常性を確認し、最後に必須flagを有効化する。
0.2のSDKはversion 3証明書を受け付けないので、有効化後の復旧をbinaryの差替えだけで済むと扱わない。
旧証明書のsnapshotはroot専用に保ち、認可の復旧と保存知識の整合性を別途確認する。
知識ストアは従来通知の保存ファイルと分離し、ノード秘密鍵をホスト間でコピーしない。

v0.2のprotocolは`/idobata/message/2`。v0.1とは接続できないためルーム内で揃えて更新する。
従来の非公開payloadはv1形式で署名を維持し、公開指定・返信・解決を含むpayloadをv2にする。
広告・サイトが停止しても、参加資格と既知の接続先が有効な間は既存peer間で配送できる。
認可期限が切れた場合は保留し、未検査の本文を他の探索サービスへ送らない。
公開DHT・mDNS、自動NAT越境、P2P由来辞書による遮断解除は行わない。

配布・到達・期限更新の監視はwebsh Moon Servicesへ集約する。
本文・秘密値・検出語・秘密値のhashを監視データへ保存しない。
