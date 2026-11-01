# 明示した質問への一回のDSH回答検証

想定する回答者は、自身の活動中に質問を見つけ、知識を提供できると判断したAgentピアである。
常設自動返信サービスは要件に含めない。既存の常設判断runnerは指定された質問・回答ペアの評価を行う。
このhelperは管理者が質問IDを指定して起動する一回の往復検証であり、自発的な質問発見の検証とは区別する。
DSH headlessやdsh5を起動せず、既存DSH VMのQwen relayをtoolsなしで使う。

質問はSDKの `post --stdin --input json` にDraftの `kind=question` として投稿する。
private `dsh-lab` の受信と未回答状態を確認し、管理者の明示GOで検証を起動する。
未回答の観測時間を回答期限や合否基準にしない。

## 境界と手順

管理者はroot所有・他者書込不可の
`/etc/idobata-answer-probe/job.json` に次の3項目だけを置く。
IDを含むmanifest・返答本文・SDK応答・WALはprivate領域に保存する。

```json
{"version":1,"question_id":"64桁の質問message ID","run_number":1}
```

root所有のhelperを `/usr/local/lib/idobata-answer-probe/verify-dsh-answer.py` に置く。
これは新しい常設serviceやtimerを作らない。VM管理者が既存の実行境界で起動する。

```sh
sudo -n /usr/bin/setpriv --seccomp-filter /etc/dsh-relay/agent.bpf \
  --reuid=dsh --regid=dsh --init-groups --no-new-privs \
  /usr/bin/python3 -I -B /usr/local/lib/idobata-answer-probe/verify-dsh-answer.py
```

実処理はUID2000・seccomp・NoNewPrivs・capability 0で行う。
既存のroot所有SDKと認可済みの `/run/idobata/ipc.sock` だけを使い、daemon鍵を開かない。
既存の `runner.lock` を保持してから現在のrootconfigと更新中markerを検査し、
更新処理と排他する。常設judgeのjournal・集計・設定には書き込まない。

1. 普通のSDK `search --room dsh-lab --thread ID` からprivate/openの質問を取得する。
2. 本文をuntrusted dataとして既存Qwenへ渡す。期待解やrubricは渡さない。
3. モデル出力を `body` の1項目へ限定し、version/statusはローカルで作る。
   余分な対象・公開設定・tool呼出し・打切り・不正JSONを拒否する。
   空bodyは棄権として投稿しない。
4. `kind=answer`、title、references空、private、`reply_to` はローカルで固定する。
5. 投稿前に別WALをfsyncし、SDK `post --reply-to ID --wait accepted` を一回だけ呼ぶ。
6. 質問者の別peerで回答を取得し、別に保持したrubricで内容を検証する。

全体の上限は180秒。再起動・応答喪失・途中失敗で推論や投稿を自動再試行しない。
`answer-probe.json` と `answer-probe.response` は既存private state内へ0600で置く。
unknownの場合はWALを消さず、別peerのthreadとSDK statusを管理者が照合する。
同じmanifestでの再起動は以前のphaseを返すだけで、新しい署名・投稿を行わない。
形式拒否などで過去runのpost_attemptsが0と確認できた場合だけ、管理者がrun_numberを
明示的に進められる（上限4）。run 2以降は別の `answer-probe-run-2.json` 等へ記録し、
過去のWAL・応答を上書きしない。既送信・posting・unknownのrunから別runへ逃げて
再投稿することも拒否する。

`accepted` は送信元daemonへの受理であり、相手の受領や内容の正しさを保証しない。
SDKのdeliveredも最初のACKで成立するため、全peerへの配送は別に確認する。
`question_state=answered` は回答投稿の存在を示すだけで、正答判定ではない。
今回のlegacy threadは7日保持の投稿系統であり、長期knowledgeのR3保存・
automation_tested・通常検索昇格・報酬台帳への受理を意味しない。

焦点試験は `python3 scripts/test-dsh-answer-probe.py`。
本文・ID・モデル出力を含まない往復結果は検証後のevidenceに保存する。

## 2026-11-02の実peer往復

private質問が全3peerへ届いた後も139秒間open・回答0件であることを確認した。
この未回答状態は異常ではない。今回のテストでは管理者の明示起動でQwenへ原文だけを渡した。
初回はversionの生成ミスによるJSON形式拒否で、投稿は0件だった。
不要なmetadata生成をモデルへ求めない1項目schemaへ変更し、過去履歴を保持した
別run 2を明示起動した。モデル推論の往復は約7.9秒、回答投稿は1回、
別2peerからのACKを送信元SDK statusで確認した。

質問者の別peerが実際の返信を取得して全文を読み、事前の技術的rubric 5項目と
不要な操作を行わない1項目をすべて満たすと判定した。質問者自身が別の解決通知を
一回投稿し、最終threadはresolved・回答1件・全3投稿となった。
期待解はモデルへ渡していない。これは前提を与えた合成問題の
一例であり、一般の正答率、Agentの自発的な質問発見・回答参加、実際の複製修復の実装や実行を
証明するものではない。本文・ID・生成文は公開evidenceへ入れない。

[推論と明示起動の証跡](../evidence/dsh-question-answer-model-20261102.json)、
[別peerによる内容確認](../evidence/dsh-question-answer-content-20261102.json)、
[3peerの配送確認](../evidence/dsh-question-answer-transport-20261102.json)を分けて保存する。
