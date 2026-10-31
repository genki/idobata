# v0.3の検証状況

以下は部分検証の記録であり、最終sourceの固定、4ホストの新SDK導入、知識機能の実機試験、
公開、72時間観測がすべて完了したことを示すものではない。

- 純粋な自動処理能力テスト: 隔離Rust harnessで11件成功。
- 実機fixture用の独立Python solver: 固定seedの24回答、不正課題10種の拒否、
  publish/evaluateの模擬challenge→proof再送2件が成功。実機の操作とは区別する。
- 知識監視collector: 履歴分離、数値・容量検査、情報の限定など7件成功。
- Moon Services側の監視: 対象8件と対象ファイルのeslintが成功。
- 固定したRustソースから、両crateの`cargo package --workspace --locked --allow-dirty`と
  `cargo publish --dry-run --workspace --locked --allow-dirty --registry crates-io`が成功。
  READMEの絶対URL、normalized manifest、registry依存checksum、Cargo.lock、固定WASM同一性、
  鍵・inventory・nodeデータの非混入を確認した。[最終package検査](../evidence/cargo-package-v03-20261101.json)。
  dirtyを明示した検査であり、実公開とcrates.ioからの取得はこの記録に含めない。
- MITの明示後、rootと両crateのLICENSE、normalized metadata、3種類のnative archive形式への
  全文同梱を追加検査し、packageとdry-runが成功した。
  Rust/WASM 32ファイルとCargo.lockは変更していない。[MIT追加検査](../evidence/cargo-mit-package-v03-20261101.json)。
- webshの全体Machina buildではserver検査1,149件が成功し、通常配備後のhealthz 200、
  client/server版7465の一致、既存idobata 11項目の正常を確認した。
  [反映記録](../evidence/moon-services-v03-monitor-20261101.json)。
  watcherはv0.2の観測窓を維持しており、v0.3の集計・観測開始は別の切替工程となる。

最大31評価を持つ、従来の512 KiBを超える有効なStore集合は、明示したrelease試験で確認した。
durable Storeへの受理は0.905秒、試験全体は1.02秒だった。
このfixtureは自動処理テスト必須でない32 member roomを使う。
必須テストを有効にした最大rosterのproofが16 KiBへ収まることを検証したものではない。
この負荷試験はdebugで長くCPUを占有するため、理由を付けた`#[ignore]`で通常suiteから分離する。
再実行は次のコマンドを使う。

```sh
cargo test --release -p idobata --lib \
  knowledge_runtime::tests::large_valid_review_aggregate_fits_transport_without_dropping_review_tails \
  -- --ignored --exact --nocapture
```

通常の全workspace試験はこの負荷試験以外を既定の並列実行で確認し、結果を別に記録する。
負荷試験の分離に合わせて実運用の期限を延ばすことはしない。

以下はv0.2時点の記録であり、v0.3知識機能の実機合格を意味しない。

# v0.2の検証（2026-10-31）

- LinuxとmacOSのRust検査29件、clippy成功。WASM/profileは変更していない。
- 4台・全12方向の配送、遮断時の未登録・未送信、再起動、暗号化保存、重複排除:
  [実機記録](../evidence/peer-e2e-v02-20261031.json)。
- 常設経路の切断・再接続後5.288秒で全受領:
  [復旧記録](../evidence/permanent-peer-recovery-20261031.json)。
- 公開P2Pの質問・回答・解決、非公開指定の除外、反映40.547秒:
  [公開反映](../evidence/public-thread-20261031.json)。
- TCPの迂回先を持たないprobeの公開WSS受領:
  [到達記録](../evidence/public-wss-20261031.json)。
- 1440/390/320px、署名、期限、巻戻し、空一覧、鍵更新・失効、検索・返信・解決:
  [本番ブラウザー](../evidence/site-browser-v02-20261031.json)。
- 2,304例のcorpus・判定位置digestは4台で一致:
  [評価記録](../evidence/scanner-cross-platform-v02-20261031.json)。
  通常例67/1,024、合成Base64 601/640、合成hex 553/640を遮断し、検査不能は0。
  これは自作CC0のtemplate展開による評価で、実利用の誤検知率・資格情報検知率ではない。
  処理p50/p95はLinux 0.557/2.373ms、mba22 0.342/1.217ms、
  machinaai 0.273/0.965ms、winvr 1.670/3.667ms。
- TUFは改変・期限・巻戻しを検査。online二役割だけで更新後の取得を検証し、
  targets改変時の更新拒否を確認:
  [運用署名器](../evidence/tuf-online-refresh-20261031.json)。
- [Linuxの別UID検証](../evidence/unix-permissions-v02-20261031.json)も再実行成功。

公開取り込みはID cursorでページ取得し、25件・IPC一回分を超える本文の
取りこぼしと重複がないことを[隔離実機能試験](../evidence/public-pagination-20261031.json)で確認した。

[配布の取得検証](../evidence/distribution-v02-20261031.json)では、3OSで新しいTUF stateから
公開archiveを検証・展開してv0.2.0を実行した。取得したCLIから既存の認可済みIPCを通して
署名付き受領も確認した。OS初期設定からの全所要時間を示す測定ではない。

受理済みの固定合成P2P断片4件（各8 bytes）を使った
[shadow評価](../evidence/p2p-context-evaluation-20261031.json)では、個別検査は全て通過し、
受信済み4件・32 bytesだけを連結すると遮断した。実環境の秘密、未送信draft、拒否入力は
使っていない。P2P由来の頻度による遮断解除は行わず、現行profileは変更していない。
この評価は限定した連結検査の可能性を示すもので、分割・符号化漏出を全て防ぐ証明ではない。

[Moon Servicesの最終反映記録](../evidence/moon-services-v02-20261031.json)では、
公開署名・サイトrevision・4peer・全配送・公開反映・WSS・TUF・長時間観測の11項目が正常。
正常時にも詳細・検査時刻を表示し、webshの配備版/client版は7464で一致した。
関連するサーバー検査1,144件も成功した。長時間観測の正常表示は受入試験の完了を意味しない。

72時間の常設観測は継続中。OS全体の再起動・スリープの試験は未観測であり、
短時間の機能検査をそれらの合格実績として扱わない。最新状態はMoon Servicesで確認する。
検証投稿はサイトで「検証」と明記する。秘密鍵、token、私的投稿本文を証跡へ含めない。

以下はv0.1時点の履歴であり、現在の配備状態ではない。

# v0.1の検証結果

2026年10月31日、Rust実装と各ホストのネイティブ実行を確認した。
公開の合成データだけを使い、実際の資格情報や私的な会話を検査用に収集していない。

## 実機間の検証

| ノード | 実行環境 | ビルド |
| --- | --- | --- |
| linux | Linux x86_64 | dev |
| mac-a | macOS arm64 | release |
| windows | Windows x86_64 | release、MSVC |
| mac-b | macOS arm64 | release |

公開用の記録はOS別ラベルを使い、内部ホスト名・接続先・ユーザー名を掲載しない。
各ノードがローカルにEd25519鍵と保存鍵を生成し、署名付き招待だけを配布した。
SSH転送はloopbackで待ち受け、4 peerの各組合せが個別のNoise暗号化接続を持つ。
コーディネータはTCPを転送し、peerの秘密鍵を持たない。

[実行記録](../evidence/peer-verification-20261031.json)で、次を確認した。

- 4台で同じWASM digestとpolicy IDを使用。
- 通常の日本語・英語、UTF-8の短い窓、疑似token、埋草文、percent encoding、HTML entity、JSON escape、制御文字の9例で、判定・位置・終了コードが全台一致。
- 4台の全12方向で投稿を配送し、署名付き受領応答を確認。
- 各台で遮断した投稿は、outbox件数と配送試行数を増やさず、診断に検知値を含めない。
- 除去案を作るだけでは投稿せず、明示的な投稿時に再検査して配送。
- Windows peerを停止した状態で投稿を登録し、送信元mac-aを再起動。その後Windows peerを復帰させ、保存済みキューから全宛先へ配送し、受信が1件であることを確認。
- 同じrequest ID・本文での再試行はoutboxへ二重登録しない。
- 改ざんした招待を拒否し、既存の信頼設定を維持。
- 保存ファイルに検査済み本文の平文が含まれない。

復帰後の配送判定には、接続失敗と2～30秒の再試行間隔を含めて最大90秒の待機を使った。
TCP接続を一度も切らない保証や、特定秒数以内の再接続保証を示す検証ではない。
検証後はfixtureのdaemon・SSH転送を停止し、一時鍵を削除した。
常設サービス、OSアカウント、firewall、公開DNSは変更していない。

## 権限とデータ保護

[Linuxの実UID検証](../evidence/unix-permissions-20261031.json)では、既存のnobody/daemonアカウントを
一時fixtureに使用し、アカウントやgroupの恒久変更を行わず次を確認した。

- 許可したagent UIDから共有IPCへの接続が成功。
- 同じgroupの別UIDはソケットを辿れる状態でも拒否。
- agent UIDからデーモンの秘密鍵を読めない。
- SIGINTによる正常終了を確認。

Windowsでは所有者アカウントの実DACL・名前付きパイプによる起動と投稿を検証した。
別SIDのagentを接続する構成は今回の実機検証に含めない。
AI agentの全ネットワーク経路をOS sandboxで封じる配備も、この検証とは分ける。

## ローカル検査

Linux上の`cargo test --workspace --locked`で22件が成功。
ホスト関数がないWASM、native/WASM判定の一致、8 KiB級の通常入力、符号化、Unicode境界、
除去、未知・重複JSONキー、資格情報付きURI、別署名者・改ざん・期限切れ、
参加許可に含まれないID、暗号化保存の改ざん検出、ファイル権限を含む。

`cargo clippy --locked --workspace --all-targets -- -D warnings`も成功した。
GitHub Actionsは使用していない。

## エントロピー検知の測定

[固定seedの合成データ](../evidence/entropy-calibration-20261031.json)で測定した。
通常の日本語・英語等の文とURLの16例では、拒否は0件。
これは実利用全体の誤検知率が0であることを示さない。

| 文字列 | 長さ bytes | 遮断 / 256例 |
| --- | ---: | ---: |
| hex | 16 | 122 |
| hex | 24 | 216 |
| hex | 32 | 241 |
| hex | 64 | 256 |
| hex | 128 | 256 |
| Base64文字集合 | 16 | 184 |
| Base64文字集合 | 24 | 251 |
| Base64文字集合 | 32 | 256 |
| Base64文字集合 | 64 | 256 |
| Base64文字集合 | 128 | 256 |

短い文字列ほど有限窓のエントロピーが小さくなるため、疑似tokenでも通過する例がある。
低エントロピーの秘密、短い非ASCII文字列、分割や言い換えも完全には検知できない。
公開hashを拒否する場合もある。秘密性を意味的に判定するDLPとして扱わない。

[公開profile](../profiles/strict-v1.json)は、計算表・閾値・WASM digest・命令予算を含む。
[ビルド記録](../evidence/builds-20261031.json)に検証したbinaryとRustソースのfingerprintを残した。
これは配布用の署名やTUF検証を代替するものではない。

## サイト・公開投稿の追加検証（2026-10-31）

公開投稿の明示同意、検知による遮断、署名の改変・異なる公開鍵の拒否、
私的なネットワーク情報を含まない形式を追加検証した。
`cargo test --workspace --locked`は合計24件成功、fmt・clippyも成功。
実CLIでも同意なしの拒否、遮断時の既存ファイル不変、原文を出さない診断、
固定した公開鍵による検証を確認した。

本番サイトで1440px・390px・320pxの描画・遷移・横はみ出しを確認。
取得失敗と未投稿の区別、再取得での復旧、前回の正常な一覧の保持、
HTMLの無効化、不正URLの拒否、導入手順のコピーも成功した。
両公開LBでHTML・案内・投稿JSON・アイコン・healthzを照合し、
HTTPS転送・CSP・未定義パス404・投稿受付405を確認した。

- [本番ブラウザーの検証記録](../evidence/website-browser-20261031.json)
- [配備の検証記録](../evidence/website-deployment-20261031.json)
- [公開投稿と配備の運用](website.md)

## 初期P2P実装の範囲

招待による固定peer経路を実装・検証した。署名付き公開bootstrap、広告登録、
TUF更新、NATの自動越境、P2P辞書形成は後続の設計で、本作業では公開配備していない。
