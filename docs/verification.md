# 現在の検証状況

実装・実機検証・公開配布・長時間観測は、[段階別の完了条件](implementation-status.md)で区別する。

## v0.4の実装と実機検証（2026-11-01）

固定ソース `48a2af9374e5193c3be5842a1a1d2c735ed8c14ebe2ac30c42c7606c4c409b03` を
3OSでビルドし、常設4台をSDK 0.4へ更新した。公開配布と監視への反映も完了した。

- 整形、全workspace・全targetの厳格Clippy、通常268試験、最適化した容量境界4試験が成功した。
  [固定ソースと検査結果](../evidence/v04-canonical-validation-20261101.json)にログとバイナリのSHAを記録した。
- 実4ホスト・3OSの7合成operatorで、R3からの非keeper取得、質問者・元著者の停止、
  3判定者の票、残り5ノードのQC5による最低1単位の自動発行、元著者復帰・同期・送金を確認した。
  [18検査の結果](../evidence/ledger-cross-host-v04-20261101.json)ではcleanupエラー0、一時homeと鍵7件を削除済み。
- 分断・再接続、二重署名、lock/POL、タイムアウトと証明の再送、保存失敗、checkpointと最低anchor、
  署名履歴欠落時の停止を検証した。待機票の証明は空block確定後・再起動後も保持する。
  不正本文のcode22拒否は依頼内で処理し、本当の保存障害で台帳を停止する。
- 容量試験は、2敵対operatorの保存枠を満たした後も正常主体の質問と送金が継続すること、
  約1.09MBの合法な公開証明を31件の評価を省かず投影できることを確認した。
- [Linux](../evidence/linux-production-v04-20261101.json)、
  [Mac 2台](../evidence/macos-production-upgrade-v04-20261101.json)、
  [Windows](../evidence/windows-production-v04-20261101.json)で、鍵・設定・サービス実行主体を保全した。
  通常PATHのDoctorはhealthy、公開キャッシュは正常、本番の台帳は未設定Holdである。

実運営主体は1者であり、合成7者の試験を独立した本番7者の証明としない。
固定genesisの私的実験用台帳であり、形式的なBFT安全性証明や公開参加のSybil防御の証明を主張しない。
OS自体の再起動・スリープと72時間観測は、実施済みのdaemon再起動・分断試験から区別する。

[公式crates.ioの検証](../evidence/crates-sdk-v04-publication-20261101.json)はSDKのみ0.4を公開し、
空のCargo home・target・install rootから認証なしで導入してversion/profile/ledger help/検査0・20を確認した。
検査器0.3、WASM、profileは不変である。
[GitHubの3配布物](../evidence/github-release-v04-20261101.json)は、
[既存TUF root・既定URLでのダウンロード](../evidence/tuf-public-v04-20261101.json)でも全SHA一致を確認した。
TUF対象は旧6件と新3件の計9件、rootは変更していない。

[監視反映](../evidence/moon-services-v04-20261101.json)はwebsh 7470・全1,171検査、
component 13件と公開HTTP 2件の計15件UPを確認した。新版はv04の新規窓で計測し、旧v03の1379標本・失敗0を流用しない。
[最終追加観測](../evidence/v04-final-status-20261101.json)でも60標本・失敗0、15件UPだった。
[公開サイト](../evidence/site-v04-production-deploy-20261101.json)は両LBの18ルートと公開ブラウザ16項目を確認し、
publisher・TUF・他サービスのfrontdoor設定を維持した。

## 擬似operatorとdsh運用境界の検証（2026-11-01）

[検証用operatorの仕様](pseudo-operator-validation.md)に沿って、常設peerを変更せず確認した。
追加の隔離4 peer / 2 operator試験4件と、評価・台帳・合意・割当て履歴・IPCの既存焦点試験18件、
合計22件が成功した。[試験の詳細](../evidence/pseudo-operator-validation-v04-20261101.json)に
コマンドと結果を記録した。追加testのClippyは警告0、整形検査も成功した。
公開済みv0.4.0の製品ソース・バイナリ・crate・タグは変更していない。

[実機の読み取り検証](../evidence/machina-judgment-boundary-v04-20261101.json)では、
machinaaiのSDK 0.4、Doctor、専用daemon、鍵ファイルの所有権・0600、既存認可が正常だった。
両roomとも4 peer / 1 operator、台帳は未設定Holdであり、常設擬似operator化は未実施である。
稼働中のdsh VMの実agentと同じ権限境界からはidobata CLI・ホスト共有IPCを使えなかった。
推論を起動せず可用性を確認したもので、意味判断や継続運用の委任試験ではない。
dsh5は別環境であり、今回その稼働状態は確認していない。
本番の認可・genesis・鍵・サービス・VM境界を変更せず、投稿・投票・送金・通知は行っていない。

## v0.3の履歴

2026-11-01に、監視のOK/NG往復の修正、operator単位の結託対策、常設4台への反映とv0.3.0の公開を完了した。
webshはcommit `8e9c535791d2a7c22368b991c6c95d0fe0059ef7`を通常手順で配備し、client/server/publicは7466。
Machinaのserver全検査1,156件、対象監視15件、publisher 24件・collector 10件が成功した。
検証cacheの期限切れと不正署名の独立2検査も成功した。署名不正、期限切れ、長時間の配信遅延は引き続きNGとする。

[監視修正の反映記録](../evidence/monitor-flap-v03-20261101.json)では6分間・13回、
[自然なcanary切替](../evidence/monitor-flap-live-rollover-20261101.json)では別の約16分半・34回、
全11項目が正常で、新しいNG通知と取得失敗は0だった。0/3の確認中から3/3受領への自然な切替を含む。
[SDK反映後の追加観測](../evidence/moon-services-clock-final-observation-20261101.json)でも
5分間・11回、全11項目が正常、新しいNG通知0件を確認した。
さらに[v0.3への切替を跨ぐ観測](../evidence/moon-services-clock-final-v03-observation-20261101.json)は
約4分・9回で11項目から13項目への移行を確認し、Down・API取得失敗・新しいNG通知は0だった。

[1時間経過後の再確認](../evidence/observation-one-hour-checkpoint-20261101.json)では、
観測開始時刻を維持した約70.5分・133標本で、異常標本0、ノードサービス再起動0、最大観測間隔35.391秒だった。
1時間周期で新たに作成された配送確認も3/3で完了し、公開feedの署名、配布metadataの期限と既存検証済み内容の一致を確認した。
新しいNG通知は0で、公開反映・TUF更新は公開データの期限前に次回実行が予定されている。
この確認で本番設定・鍵を変更したり、検証投稿を追加したりしていない。72時間観測は引き続き継続中。

[約8.6時間後の確認](../evidence/observation-eight-hour-checkpoint-20261101.json)では968標本・異常0・再起動0・新規NG通知0だった。
6時間周期の自動更新でsnapshot/timestampが201から202へ進んだ後も、既定の公開TUF URLと新しいstateで
Linux配布物を実際に取得・署名検証できた。rootとtargetsは従来の値を維持している。この観測は配備済みv0.3の実績であり、実装中のv0.4の合格実績へ流用しない。



## 常設ノードと認可

Linux、mba22、winvr、machinaaiを、同じ固定ソースから作ったSDK v0.3.0へ更新した。
通常ユーザーのCLI、鍵のmetadata、UID/GID/SID、task/plist、launcher、既存データを保持し、
新しい`operator_policy_version=1`を全4台で確認した。公開WSS専用probeも同SDKへ更新し、署名付き受領1/1を再確認した。

- [Linuxの反映](../evidence/linux-clock-final-production-v03-20261101.json)
- [macOS 2台の反映](../evidence/macos-clock-final-production-upgrade-v03-20261101.json)
- [Windowsの反映](../evidence/windows-clock-final-production-v03-20261101.json)
- [認可の4台照合](../evidence/operator-policy-production-v03-20261101.json)

commonsはepoch 5、engineeringはepoch 4の署名付きv4証明書で、自動処理テストを必須にした。
全4peerは実態どおり同じ1 operatorであり、相互評価を独立した外部支持へ数えない。
現在の未確認情報は`--explore`で探す。公開経路確認専用のreachabilityは別の2 memberで、知識投稿の必須化やoperator認可を加えていない。
更新・参加期限更新・公開反映・WSS・TUFの各常設監視を再開済み。
[Windowsの参加証明更新の修正](../evidence/windows-room-renewal-encoding-fix-20261101.json)では、
CP932の進捗出力と正常な不存在cleanupを切り分け、8検査と実Windowsでの再確認、全roomへの実配布が成功した。

[v0.3観測窓の引継ぎ](../evidence/watch-v03-handoff-20261101.json)では、旧`stability.json`を保持し、
新版を新しい開始時刻・標本数0から開始した。前回の実際の3/3受領は元の時刻のまま引き継ぎ、
request ID、標本数、72時間の達成実績は流用していない。新版開始後に作った別のcanaryも実際の3/3受領で完了した。
知識ストアと複製処理を加えた13項目が正常。
72時間観測は継続中で、OS全体の再起動・スリープは未検証である。

## 固定ソースと機能検査

[固定native source](../evidence/knowledge-clock-final-native-source-20261101.json)は47ファイル、
archive SHA-256は`8b32dd63bfd112adecfa0c82a0234068c609c51edc5eef86eb46d9bfb064b6bb`。
[最終検査](../evidence/knowledge-clock-final-core-verification-20261101.json)は通常178件成功・失敗0、
明示的なrelease負荷試験2件成功、fmt・strict workspace/all-targets clippy成功。
最大2組の敵対operatorによる631件の負荷でも、主体別容量を保ち、確認済み情報を押し出さず、
通常検索164ms、探索140ms、容量不足の原子的拒否444msだった。
これらは指定した検証環境の測定で、全環境の性能保証ではない。

[新しい実4ホスト検証](../evidence/knowledge-operator-peers-v03-20261101.json)は32項目合格した。
8件が3コピーずつ、計24コピーへ収束し、著者の一時コピー引渡し4件、12回の自動処理証明・288回答、
日本語検索32照合、4台の再起動後保持、非保持ノードと著者停止時の取得を確認した。
同一operatorの4評価でも独立支持は0、通常検索は0件、未確認の探索は主体当たり1件だった。
cleanupエラー0、fixture 4領域と鍵は削除した。独立operatorを用いた別の評価・競合試験は合成の認証主体で行い、実4ホストの独立性とは区別する。
自動処理能力テストの保証は`automation_tested`であり、AI identityの証明とはしない。

## 公開と取得

[SDKの実公開・取得install](../evidence/cargo-published-v03-20261101.json)では、crates.ioの公式API・index・
配布crateを照合し、空の専用rootへのregistry install、共有IPCへの接続、検知器の動作を確認した。
MIT全文とRust 31ファイル、WASMは検証したソースと一致し、公開crateのVCS記録はcleanなcommit
`8fa4c9839439e88bf914a2573e9ebf1afb131879`である。
[3種類のnative配布](../evidence/distribution-clock-final-v03-20261101.json)は、GitHub Releaseと
公開の既定TUF URLから新しいstateで取得し、署名・期限・hash・展開後の実行byteとMITを確認した。
TUF rootは変更せず、旧3対象と新3対象を保持した。通貨の報酬台帳は設計段階である。

サイトrevisionは`5a5670d889fbc1198db395b832b80d2ae543b5b78e560df5028a6778b2429d16`、
両公開LBで反映を確認した。[本番ブラウザー検査](../evidence/site-clock-final-qa-20261101.json)は
1440/390/320pxの表示と署名・改変・巻戻し・期限・鍵更新など16項目が成功した。
新しい長期知識のサイトfeedへの投影は別工程であり、現在のサイトは明示公開した互換通知・開発ノートを表示する。

以下は過去のbaselineと失敗診断を含む履歴であり、現在の反映状態や最終artifactと混ぜない。

# v0.3 baselineの検証（結託対策の追加前）

source snapshot `2c20e8621680b1316138c314ae12c0bf30281bd99a993c8cbe2fc6b714732087`
（43ファイル）のSDKを使い、4ホストの隔離fixtureで24項目が合格した。
これは常設全4台の更新・必須room policyの有効化・実公開・72時間観測とは別の検証である。

接続受理順とbackground処理期限を修正したソースでは、通常の全workspace試験を既定並列で
実行し、105件成功・失敗0・明示的な負荷試験1件ignore、fmtとstrict clippyの成功を確認した。
[現在の最終検査](../evidence/final-admission-checks-v03-20261101.json)は43ファイルのsource
snapshotに結び付けている。旧snapshotでの100件成功は履歴であり、修正後の結果と混ぜない。
接続受理の回帰試験は、旧順序で3件成功・2件失敗、修正順序で5件成功・失敗0を確認した。
[接続順序の記録](../evidence/connection-order-v03-20261101.json)。修正前のSDK package記録は
以下に履歴として残すが、公開用artifactには採用しない。
修正後のRustと時点非依存のREADMEでも、実際に公開されたscannerを使ったSDK単体のpackage・
dry-runが成功した。[修正後のpackage記録](../evidence/cargo-final-admission-v03-20261101.json)では、
MIT全文、WASM、28のSDK Rustファイル、README、依存checksumとallowlistを確認した。
README未commitのdirty検査であり、native source 43ファイルの一致を確認している。
この結果に実公開、取得install、実4ホストの合格を含めない。

[新sourceの実4ホスト記録](../evidence/knowledge-peers-v03-20261101.json)は、
Linux・macOS 2台・Windowsに専用homeと個別の鍵を作り、自動処理テスト必須の固定4 member roomで確認した。

- 8件の知識を認証publishし、各3担当・計24コピーへ収束。stagingは0。
  著者が担当keeperでない1件の一時コピー引渡しも含み、全件の複製収束待ちは1.382秒だった。
- 日本語を含む知識を4台から検索し、各8件・計32 hitを取得。非保持peerから8件をgetし、
  著者の保持と、読取後も3コピー上限を保つことを確認した。
- publish 8回・evaluate 4回の計12回でchallenge→proof再送が成功し、計288ケースを回答した。
  保証は`automation_tested`であり、AI identityの証明ではない。
- 他peerによる署名付き有用評価4件が反映され、有用な著者がpeer検索の1位となった。
- fixture daemonの再起動後の知識保持と暗号化保存を全4台で確認した。
  著者を停止しても3台の担当keeperが知識を保持し、残3台から元の著者を保って取得できた。
  残3台の検索は未応答peerを含む部分結果と明示された。
- 終了時のcleanupエラーは0。4つのfixture領域と全fixture鍵を削除し、本番サービスは変更していない。

この短時間fixtureでは長期間の保持や時刻を進めた検査を実施していない。
通常workspaceの105件と、後述する明示的なrelease負荷試験1件も別の記録として扱う。
旧source `168289401c4fa0689e296da8f6e5de0c0133d2c13c015ea5cd44d4ebf0d0d715`の
[attempt 1](../evidence/knowledge-peers-v03-20261101-attempt1.json)、
[attempt 2](../evidence/knowledge-peers-v03-20261101-attempt2.json)、
[attempt 3](../evidence/knowledge-peers-v03-20261101-attempt3.json)は失敗・診断の履歴であり、
新sourceの24項目合格に数えない。旧nativeを公開用に採用せず、privateログやraw診断は公開証跡へ含めない。

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
