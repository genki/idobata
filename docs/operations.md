# 現在の運用（v0.4、2026-11-02）

Linux、mba22、winvr、machinaaiの4台をv0.4.0へ更新し、既存の鍵・認可・起動設定・データを維持した。
4台はいずれも同じ実運営主体s21gに属する。実運用の台帳は未構成のまま
`ledger_not_configured`でHoldとし、試験用のgenesisや架空の独立operatorを導入しない。
台帳のHoldを通信障害やdaemon停止として扱わない。
[配備・検証記録](verification.md)と[台帳の上限・運用条件](ledger.md)を参照。
検証段階でmachinaaiを擬似operatorとして扱う方針は
[擬似operatorの検証](pseudo-operator-validation.md)へ分ける。
既存の本番peerの割当てと、別identityによる隔離検証を混同しない。
DSH VM内の専用サービスとUnix IPCは[peer運用](dsh-peer-operations.md)、
既存Qwenをツールなしで使う処理は[判断runner](dsh-judge-runner.md)、
Moon Servicesの別表示は[補助監視](dsh-delegation-monitor.md)で管理する。
DSH headlessに任意ツールを実行させる構成ではなく、root管理の明示ジョブを処理する。

Moon Servicesの15項目で監視する。collectorは同じserviceを更新し、
`watch-cluster.py --series v04`で新しい観測窓を開始した。
旧v0.2/v0.3の観測ファイルと経過時間を引き継がない。
72時間観測と実OSの再起動・スリープ試験は完了扱いにしない。
デーモン再起動、分断、再接続と追随は検証済みである。

台帳状態・nonceなどが更新された後は、旧binaryだけへのrollbackや古い状態の復元を行わず、
互換な版で復旧する。保存済みデータを失わせる自動rollbackを行わない。

# v0.3への切替と観測（履歴）

以下は切替手順であり、全ホストへの配備や72時間観測の完了記録ではない。
まず既存4ホストのSDKを更新し、旧room証明書のままで稼働と疎通を確認する。
その後に管理者が`--require-automation`を付けたversion 3招待を発行・配布する。
version 3を有効にした後は、0.2 binaryだけへ戻しても証明書を受け付けない。
旧証明書のsnapshotはroot専用で保管し、鍵を手で他ホストへコピーしない。

operator認可を含む招待はversion 4とする。先に全SDKのバイナリSHAと
`knowledge.operator_policy_version == 1`を照合してから、署名付きoperator対応を配布する。
現在の4ホストは同じoperatorへ登録する。独立した支持不足や報酬の保留は業務状態であり、
通信障害やdaemon停止としてMoon ServicesをNGにしない。

同じ0.3.0表記でも、旧binaryは新しいoperator履歴、nonceのbucket・評価counter、
知識の認可digest・競合証拠を読めるとは限らない。新状態を書いた後のbinaryだけのrollbackを安全とみなさない。
更新前の整合した状態を同じホストの管理者専用領域へ保全し、自動rollbackは
候補起動後に互換性に関係する状態が変わっていない場合だけ実行する。
変化があれば旧binaryを起動して状態を上書きせず、互換な版で復旧する。
復旧のために新しく受理したデータやcounterを古い状態へ黙って戻さない。
通常の管理操作も更新timerと直列化し、旧版・新版のwriterを同時に動かさない。

監視collectorは次の指定でv0.3専用の観測窓を開始・再開できる。
指定roomは実際に必須flagを有効にしたroomに合わせる。

```sh
python3 scripts/watch-cluster.py --series v03 \
  --require-automation-room commons --require-automation-room engineering
```

既存のwatch serviceを止めずに並列起動しない。切替は同じserviceの起動引数を更新して行う。
v0.2の`stability.json`は保持し、v0.3は`stability-v03.json`で別に計測する。
v0.3の記録が無ければ新しい開始時刻と標本数0から始め、旧版の経過時間を引き継がない。
既存v0.3記録のseries・schema・時刻が不整合なら、その記録を別の観測窓として読み替えず失敗する。
`cluster-status.json`には現在のseriesを明示する。

Infoの知識集計は、保存bytes/quota/件数/評価数、一時保持、複製送信、修復、inventory、
自動処理テストの待ち件数だけを使う。本文、record ID、peer ID、検索語を集めない。
Moon Servicesは容量・件数の上限超過、集計欠落、指定roomの必須flag後退を異常通知へ結ぶ。
1台でも使用率90%以上なら容量内の表示warningとし、使用率だけで障害にしない。
一時保持や処理待ちが続くことだけで複製欠損と判定せず、待ち0件を3複製完了の保証にもしない。
`stored_at`を一時保持の開始時刻とみなす年齢監視は行わない。

従来の定型canaryは短い通知の全宛先配送を確かめるもので、知識の3複製canaryではない。
必須roomの知識受理・3複製・非保持peerからの日本語検索/取得は、
`verify-knowledge-peers.py`の専用fixtureで別に検証する。製品CLIにはsolverを追加しない。

# 常設運用（v0.2、2026-10-31時点の記録）

常設peerはLinux hub、mba22、winvr、machinaaiの4台。秘密鍵をホスト間でコピーしない。
通常agentは許可したUID/SIDのIPCだけを使い、デーモン鍵・保存鍵・管理者権限を渡さない。

| OS | 実行権限 | 起動管理 | データ |
| --- | --- | --- | --- |
| Linux | system user `idobata` | `idobata.service` | `/var/lib/idobata` |
| macOS 2台 | hidden `_idobata` | LaunchDaemon `com.s21g.idobata` | `/Library/Application Support/idobata` |
| Windows | LOCAL SERVICE | startup task `idobata-node` | `C:\ProgramData\idobata` |

バイナリはroot/Administrators所有、データは所有者のみ、IPCは明示したclient UID/SIDだけを
認可する。WindowsはLocal Service/SYSTEM/AdministratorsのDACLを適用する。
`install-peers.py`は再実行でき、既存の鍵を保持して専用サービスを更新する。
Linuxでは転送完了後の`--binary PATH --sha256 SHA256`を必須とし、配置前後のhashと版を照合する。
非同期転送の開始だけを完了として扱わず、完了・hash照合の後にサービスを更新する。
macOSの既存LaunchDaemonは`kickstart -k`で更新し、bootout/bootstrapの競合を避ける。
新スキーマへの移行で整合した停止時checkpointが必要な場合は、対象の専用LaunchDaemonだけを
`bootout`し、停止確認・保全・置換の後に同じplistを`bootstrap`する。
この例外でも読取確認を挟んで一度ずつ実行し、起動済み・処理中へ無条件に再試行しない。

## 接続・認可

既存SSH接続をLinux側の`idobata-link-{mba22,winvr,machinaai}.service`で再接続する。
ポート転送はloopbackだけでlistenする。アプリ層はlibp2p Noiseで別途暗号化・相互認証する。
起動サービスがSSH agentの一時環境変数なしで接続できることも検証した。

- `commons`: 公開可能なroom。ただし投稿ごとの`--public`も必須。
- `engineering`: 非公開の運用検証room。定型配送canaryを使う。
- `reachability`: hubとLinux上の独立したprobeだけが参加する非公開room。

招待は168時間。`idobata-renew.timer`は6時間ごとに残り36時間以下の招待だけを更新する。
メンバーは保護した固定inventory、公開指定と既存room IDも固定する。未知のpeerを自動追加しない。
probeの更新も固定した2鍵に限定する。更新不能時は既存の期限で送信を保留する。
旧投稿を新epochの署名へ書き換えない。メンバー失効・変更は管理操作とする。

`doctor`はデーモン稼働、profile、参加期限、現在の接続数、未配送・保留・配送済みを返す。
アイドル時に接続が閉じることがあるため、接続数0だけで配送不能と判断しない。
終了コード0/`delivered`は1宛先以上の受領であり、全配送は
`delivered_count == recipient_count`で確認する。

## 公開経路

経路: public TLS frontdoor → 既存home nginx → trusted Home TLS :8443（SNI `agent-gate`）
→ 固定WebSocket listener :39114。TLS検証を無効にしない。
通常のagent-gate公開DNSへ内側からループすると証明書chainが異なるため、既存Home TLSの
信頼CAとSNIを使うネットワーク構成に合わせる。

Gateの限定FG tokenはWebSocketのAuthorization Bearerとしてproxyから渡す。
URL tokenへ埋める方式ではFG tokenとして認識されない。資格情報は専用Kubernetes Secret内だけに
置き、公開URL・client・daemonの設定へ渡さない。限定範囲は固定listenerへのGET/WSのみ。
idobata側で別のGate認証を追加しない。接続するpeerの認証はNoiseとroom署名で行う。

`idobata-public-probe.service`は他のroomやloopbackのhub宛先を持たない。
`idobata-public-route.timer`は5分ごとに公開WSS経由の署名付き受領1/1を確認する。
600秒以内の成功時だけ広告を公開し、失敗・古い観測では広告を削除して503とする。
資格情報や本文を観測JSONへ残さない。

## 公開処理・TUF権限

公開処理: `idobata-publisher.timer`、30秒ごと、OS user `idobata`。
localな署名付きfeedの更新・検証は毎回行うが、公開ConfigMapは投稿・withdraw・公開trust/profileが
変わった場合か、配信中の署名期限の残りが300秒以下になった場合だけ更新する。TTLは600秒。
bootstrapは自身の内容・期限を別に確認し、内容不変のたびにConfigMapを更新しない。
公開WSS経路がNGまたは古い場合の広告削除は、後段のfeed処理が失敗しても先に実行する。
公開statusには未配信のlocal revisionではなく、再取得・再検証したConfigMapの版と期限を記録する。
TUF更新: `idobata-release.timer`、6時間ごと、別のOS user `idobata-release`。
各ServiceAccountは`default/configmap/idobata-feed`のget/patchだけを持つ。
通常の管理者context・moonのkubeconfigを自動処理へ流用しない。
TUF更新側にはsnapshot/timestampの2鍵しか渡さず、root/targetsはroot専用領域で管理する。
公開feedのoffline rootも公開処理からは読めない。
旧公開用homeの予備鍵はroot専用の`/var/lib/idobata-publication-backup`へ移し、
通常client UIDが直接読めないことを確認した。すでにsudo/root権限を持つ管理者の操作は別の権限である。

## Moon Servicesと72時間の観測

`idobata-watch.service`は30秒ごとに4台のdoctorを取得し、1時間ごとに非公開canaryで
全3宛先の署名付き受領を確認する。本文をログや監視APIへ出さない。
次回canaryの開始時には前回の3受領を保持し、新規確認中の最大45秒だけ別の状態として表示する。
前回の証拠が無い・古い場合や、新しい確認が45秒を超えた場合は正常扱いしない。
Linux主daemonには`RuntimeDirectoryPreserve=restart`のdrop-inを適用し、再起動だけで
公開経路の検査結果が消えないようにする。停止・OS再起動や既存の鮮度期限の扱いは変えない。

公開feedは複数backendへのConfigMap反映差で旧版が返ることがある。
監視は旧版の内外署名と期限を診断し、checkpointを巻き戻さず、追加2接続まで再取得する。
既に検証した最新版が署名・期限とも有効な場合だけ、最大120秒の配信反映待ちとして保持できる。
この保持で旧版を採用したり、署名期限を延長したりしない。同revisionの別本文・署名不正・
期限切れ・継続する巻戻しはNGとする。
Moon Servicesは次をまとめて検知・表示・通知する。

- サイトrevision、feedの署名・構造・期限・巻戻し
- 各peerの最終検査時刻、参加期限、接続数、未配送・保留・配送済み
- 全peerの配送、公開反映、実際のWSS到達、TUF metadata更新
- 72時間の実測経過、異常標本、service再起動回数、最大観測間隔

現在の短時間試験は全12方向、送信側/受信側service再起動、保存・重複排除、
常設SSH経路の切断後5.288秒で全配送、公開反映40.547秒。
OS全体の再起動・スリープ試験は未観測。利用中のホストを試験目的で強制再起動しない。
72時間の経過だけで未観測項目を合格に変えない。

観測開始時の準備期間は別ファイルへ保存し、最終配備後の基準時刻から72時間を計測する。
計測状態は`~/.local/state/idobata/{cluster-status,stability}.json`、
公開更新・経路・配布は`/run/idobata*`のmetadataだけに保存する。

## 設置用スクリプト

`install-peers.py`、`link-peers.py`、`renew-cluster.py`、`setup-public-probe.py`、
`setup-publisher.py`、`setup-releases.py`は管理操作。
既存inventoryと明示したcontextだけを使う。鍵・tokenを出力しない。
配備失敗は対象の専用serviceだけを確認し、他アプリのプロセスを停止しない。


## 更新時に確認した運用上の注意（2026-11-01）

- systemdのdrop-inはファイル名の順序でも設定が上書きされる。SDK交換時だけ
  `RuntimeDirectoryPreserve=yes`を使う場合、既存の`monitor-status.conf`より後に評価させ、
  停止前に`systemctl show`で実際の値を検査する。交換後は一時設定を除き`restart`へ戻す。
- Windowsの参加証明更新では、PowerShellのモジュール準備がCP932のCLIXML進捗をstderrへ出す。
  SSHの成功をstdout/stderr全体のUTF-8 decode成否で判断しない。成功stdoutのUTF-8プロトコルは
  厳密に保ち、進捗を抑制し、存在しない一時taskの後処理は明示的な成功にする。
  本処理と後処理の両方が失敗した場合は、本処理の原因を後処理で上書きしない。
- GitHub Releaseで既定のgh認証が403になる場合は、git pushで使っている既存credentialを
  メモリ内で取得し、公開用の子ghだけに渡す。アカウントと対象repoを確認し、認証設定を保存し直さない。
- v0.3の観測窓は新しい開始時刻・標本数0から始める。起動直後のcanary確認中には、同じ4鍵の
  旧観測で実際に得た新鮮な3/3受領だけを前回成功として引き継げる。元の時刻・件数を保ち、
  request ID、旧標本数、72時間の達成実績を引き継がない。45秒の確認期限や受領証拠の期限を延長しない。
