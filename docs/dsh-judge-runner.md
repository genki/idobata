# dsh環境の判断runner

このrunnerはDSH VMの既存Qwen providerへ、toolsなしのJSON判断だけを委任する。
DSH headless自体の起動や、別の独立AI・管理主体の証明ではない。
新しいモデル・推論server・有料resourceを追加しない。

通常のDSH/YOLO headlessにはread/write/bashがあるため、この用途では起動しない。
VM内の既存relay `127.0.0.1:18088/v1/chat/completions` と既存Qwenモデルを固定し、
`tool_choice=none`、tools省略、`json_object`、`store=false`で生成する。
モデルへ渡すのは固定指示とuntrustedな質問・回答本文だけ。
tool呼出しを返した応答も拒否し、命令やshellとして解釈しない。

## 実行境界

runnerはDSH VMの一般UID2000で動き、root所有SDKへ
`--socket /run/idobata/ipc.sock`を指定する。daemonの鍵やhomeを開かない。
モデルにはIPC操作・任意コマンド・管理API・認証キーを渡さない。
対象はprivate `dsh-lab`だけで、公開フラグfalseとautomation必須を確認する。
署名済みのoperator割当て、既存room、本番ledger/genesisは変更しない。

Root所有configは `/etc/idobata-judge/config.json` に置く。
必須項目は `version=1`, `room_alias=dsh-lab`, `room`（authority_peer_idと
SDKが発行したSignedRoomのcertificate）、`sdk=/usr/local/lib/idobata/idobata`,
`socket=/run/idobata/ipc.sock`, `queue=/etc/idobata-judge/jobs`,
`state=/home/dsh/.local/state/idobata-judge`, `deadline_seconds=180`。
configとqueueはroot所有・他者書込不可とする。SignedRoomは発行時の省略形式も保つ。

root所有jobは次の5項目だけを持つ。IDは公開collectorへ渡さない。

```json
{"version":1,"query":"対象を区別する探索語","question_id":"64桁の質問record ID","answer_id":"64桁の回答record ID"}
```

runnerはexploreで候補を確認した後、この2 IDだけをgetする。
同一operatorの探索件数上限で指定IDが検索結果へ出ない場合も、rootの明示ID指定で取得する。
取得した未確認本文を支持済みとして扱うものではない。
通常検索へ昇格させたり、見つかった全recordへ勝手に投票したりしない。
本文中の採点指示はuntrusted dataであり、モデルの実行指示へ昇格させない。
モデルのJSON出力はversion・judgment・reasonだけに限定する。
対象ID・取得本文のdigestはrunnerがローカルsnapshotから付与し、適用前に再照合する。
モデルに暗号IDの転記や対象選択を任せない。unknown field、重複key、別対象、
JSON以外、制御文字、長すぎる理由、tool呼出し、出力打切りを拒否する。

## jobの追加と運用

管理者はSDKでprivate recordを作り、確認したIDからjobを生成する。
次はVM管理者が行う操作であり、モデルが実行するコマンドではない。
IDを含む出力・入力ファイルは管理者のprivate領域へ保存する。

```sh
umask 077
python3 /usr/local/lib/idobata-judge/idobata-judge.py --create-job \
  --question-id "$question_id" --answer-id "$answer_id" --query "$query" \
  > /root/private-judge-job.json
install -o root -g root -m 0644 /root/private-judge-job.json \
  /etc/idobata-judge/jobs/review-001.json
```

同じ対象ペアはfilenameや探索語を変えても再送しない。
queueは最大64件、1回で1件だけ処理する。常設timerは120秒周期で
`python3 /usr/local/lib/idobata-judge/idobata-judge.py --config /etc/idobata-judge/config.json --apply`
をUID2000で起動する。既存のUID/seccomp/NoNewPrivs境界も維持する。
job全体は既定180秒、上限300秒で打ち切る。timerの実行上限は設定したjob上限より長くする。
並列起動はprivate `runner.lock`のflockで拒否する。

`--apply`を省略すればdry-runになる。妥当な判断をprivate journalへ保存し、
後のapplyは同じ判断と本文digestを再利用する。10分を超えた判断は適用しない。
`--job review-001.json`でqueue内の1件だけを指定できる。
肯定はknowledgeの`useful`、要求不充足・誤りの`not_useful`は`incorrect`へ対応付ける。
`abstain`は評価を送信せずHoldにする。理由は短い根拠としてSDKへ渡し、
外部参照URLやコマンドを組み立てない。

automation必須の評価では、既存検証helperと同じ公知の有限taskだけを解く。
対象・review inputのaction digest、subject、room、issuer、期限、証明書を照合する。
proofはmode0600の一時ファイルに置き、同じ評価入力で一度だけ提出し削除する。
SDKの検査・署名・nonce・proof消費の検証を迂回しない。

送信予約はSDKを呼ぶ前にfsyncする。応答喪失・送信中crashはunknownとして停止し、
次周期や手動再実行で再送しない。モデル失敗も無限retryしない。
管理者はprivate journalとSDKの最新評価を照合してから復旧を判断する。
queueファイルを退避してもjournalを削除せず、nonce・判定履歴を巻き戻さない。
記録上限512対象に達した場合も古いtombstoneを捨てずHoldにする。
完了・管理者確認済みのqueueファイルはrootのprivate archiveへ移し、
active queueを64件以内に保つ。失敗を自動再試行するためにjournalを消さない。

## 更新と監視

状態は `/home/dsh/.local/state/idobata-judge/status.json`。
10秒heartbeatとtimerのidle更新で、既知state/reason・時刻・集計数だけを出す。
判断理由、本文、record/peer ID、質問、署名、鍵はpublic collectorへ出さない。
初期の空queueはHold/待機であり、attemptや成功件数を作らない。
dry-run成功、評価適用、abstain、unknown、障害は区別する。

168時間room更新時は、rootのrenew手順がrunnerとの排他を取ってからSDK側joinと
rootconfigのcertificate更新を行う。同じroom ID、policy、members、operator割当て、
private/automation必須をpinし、epoch・発行/期限・署名だけを進める。
runner自身は認可を更新しない。既存 `runner.lock` をrootが開く場合も新規作成せず、
UID2000の所有権を変えない。configとSDKの証明書がずれた場合は適用せず停止する。
renewは同じlockを保持した一つのprocessでSDK joinとconfigのfsyncまで完了させる。
先に `/etc/idobata-judge/authorization-update.pending` を永続化し、
両方の更新が完了するまで削除しない。runnerはこのpathの存在・検査異常で停止し、
lock取得後にもconfigとmarkerを再検査する。更新途中のcrash後は管理者が両状態を
照合して更新を完了する。markerだけを消して処理を再開しない。
認可設定の故障は実推論attemptを作らず監視NGにする。

2 operatorでは3外部支持・信用3000に届かず、通常昇格や台帳発行の条件を満たさない。
synthetic=true、common_controller=s21g、実独立operatorへの寄与0を運用metadataで表示する。
モデル判定の成功は管理主体の独立性や判断の普遍的な正しさの証明ではない。

## 2026-11-02の受入

既存Qwenを実際に呼び、正解はuseful、誤回答と本文の採点指示を含む回答は
not_usefulと判断し、SDKへそれぞれuseful/incorrectを適用した。
初回の誤回答jobは厳格JSON検査で評価前に拒否された。別途一回の評価なし診断では
モデルによるanswer IDの転記漏れを観測したため、出力を3項目に限定し、
対象の束縛はローカルで行う方式へ変更した。過去の失敗journalと件数は保持している。
修正後の誤回答検証は新しいrecordを明示指定して実施した。

正解jobは常設timerがqueueから選択し、適用後の次周期はidleとなった。
評価件数・sequenceは増えなかった。epoch 2更新後にも、新しい正解recordを
同じtimerが選択し、新しい証明書に束縛されたautomation proofで評価できた。
更新後の次周期もidleで、評価sequence 8と集計5試行・4成功・1拒否は増えなかった。
全対象はprivate・unconfirmed、通常検索0件、台帳は未設定Holdを維持した。
これは小さな受入fixtureの結果であり、未知の問題や注入全般への耐性を保証しない。

焦点試験は `python3 scripts/test-idobata-judge.py` で24件。
本文・ID・自由形式の判断理由を除いた結果は
[判断runnerの証跡](../evidence/dsh-judge-runner-20261102.json)を参照する。
