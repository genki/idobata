# DSHの補助監視

DSHの専用検証peerとQwen判断runnerは、常設4peerのcollector、3宛先canary、
v0.4の72時間観測窓から分離する。製品SDKや署名Roomのschema変更は不要。
Moon Servicesのidobataへ補助2行を追加する。

このpeerは`synthetic=true`、`operator=machinaai-test`、
`common_controller=s21g`、`executor=dsh`、`model_provider=qwen`、
`model_tools=false`、`actual_operator_contribution=0`である。
別の鍵・daemonを使っても、実際の独立operator数や台帳のquorumへ加算しない。
DSH既存relayの判断実行であり、dsh5やdsh headlessそのものの利用を意味しない。
運用metadataは管理者が固定する表示上の区分で、独立性やAI由来の暗号証明ではない。

`scripts/watch-delegation.py`は既存SSHの`machinaai`から、既存Limaの
`dsh`へ接続する。VMを自動起動せず、UID2000の既存`dsh-websh-exec`を通る。
専用IPCへの`doctor`とrunnerの`status.json`だけを読む。
collectorが専用daemonのhome・鍵・モデルのpromptや出力本文を読むことはない。
stdout/stderrは上限付きで処理し、自由なerror文字列、peer/record/roomの識別子や
モデル出力を監視ファイルへ保存しない。

監視用状態はLinuxの`~/.local/state/idobata/`へ0600で保存する。

- `delegation-watch.json`: 固定した読み取り専用command。公開しない。
- `delegation-monitor.json`: 機能のenabledと固定の共通管理metadata。
- `delegation-status.json`: 30秒ごとの、許可した集計値だけの観測。

runnerの元状態はguest内の`/home/dsh/.local/state/idobata-judge/status.json`。
10秒のheartbeat、1job既定180秒・最大300秒、定期確認120秒である。
Moonはcollectorの鮮度120秒、runnerのheartbeat180秒を検査する。
idle時の定期更新120秒にSSH取得・起動の余裕を持たせる。
期限を超えた実行中jobはtimeoutとして表示し、確定していない失敗件数を加算しない。

| runner状態 | Moon表示 | 成功扱い |
| --- | --- | --- |
| success / dry_run_complete | UP・判断試行完了、適用なし | 判断試行だけ完了 |
| success / evaluation_applied | UP・評価適用 | はい |
| hold | UP・理由付きの待機 | いいえ |
| not_run / running | UP・未実行pending / 未完了の実行中 | いいえ |
| failure / timeout | DOWN・固定の失敗理由 | いいえ |
| IPC不可、欠測、古い状態、不正metadata | DOWN・unavailable | いいえ |

空queueや全job完了後の`hold/no_open_questions`、`hold/no_eligible_answer`は
試行ではないため、attemptsやholdsを増やさない。初期値0や過去の累計値を保ったまま
UP待機として表示する。heartbeatが古ければ、この待機もunavailableになる。

画面の累計「成功N」はrunnerの処理成功数で、dry-runや重複完了の確認も含む。
評価をN件適用したという意味ではない。実評価の適用は現在の
`success/evaluation_applied`だけを`evaluation_applied=true`として表示する。

有効化は専用peerとrunnerの準備後に行う。準備中は設定が無いかenabled=falseなので、
構築途中の欠測を既存監視へ流さない。一度有効化した後のstatus欠落・期限超過は
正常扱いしない。モデル失敗や適用結果不明を保留・成功へ読み替えない。

```sh
python3 scripts/setup-delegation-monitor.py
# 専用peer/runnerの準備と通常WebSH配備が完了してから実行する。
python3 scripts/setup-delegation-monitor.py --apply
```

管理helperは有効な実Doctorとrunnerの状態schemaを検査してから、専用の
`idobata-delegation-watch.service`だけを設置・起動する。最初のstatusを原子的に
保存してからenabledを保存し、切替途中の欠測を避ける。既存のwatch.service、
publisher、renew、4peerのdaemonや観測履歴には手を加えない。
runner自身が記録した失敗はschemaが有効なら監視へ表示する。成功するまで
有効化を遅らせて失敗を隠す運用はしない。

検査は既存のPythonとNodeで直接行い、GitHub Actionsや常設有料サービスを追加しない。
通知はMoon Servicesの既存検知に集約し、手動のTalker・Slack通知を送らない。

## 踏み台経由の接続失敗対策

2026-11-02、監視SSHのbanner交換が5秒で失敗し、peerとrunnerが同時に
DOWNへ揺れる事象を確認した。外側SSHの接続猶予は12秒、取得全体は30秒とし、
接続タイムアウト・SSH接続失敗だけ一度再取得する。失敗が続けば従来どおり
unavailableとする。モデル失敗、不正JSON、期限切れを成功へ読み替えない。

取得子プロセスは専用process groupで起動し、終了・期限超過時にはProxyCommandも
回収する。journalへ失敗分類・試行回数・経過時間、再取得での復帰を記録する。
任意stderr、接続先、鍵、モデル出力は記録しない。表示側の鮮度判定は変更しない。

検証では旧設定の並列取得4回中3回で両SSHが約5.0秒でbanner交換timeout、
1回では約2.1秒で両方取得できた。接続12秒だけでも一時失敗を再現したため、
猶予延長だけに依存せず限定再取得を追加した。変更前にも正常取得時のdaemon
uptimeは継続しており、DOWNの直接原因は対象停止ではなく監視経路の取得失敗だった。
Python 15件とwebsh側の表示判定9件を検証し、専用collectorだけへ反映した。
websh配信物は変更していないため、webshのbuild・再起動は不要。
