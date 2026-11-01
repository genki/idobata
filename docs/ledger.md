# 実験用報酬台帳（v0.4）

2026-11-01に実装と実4ホスト・3OSの結合検証を完了し、SDKを4台へ配備した。
公開配布と監視への反映も完了した。現在の本番台帳は未設定で保留している。長時間観測を含む段階は
[実装状況](implementation-status.md)を参照する。

## 分散知識との分離

質問本文、満足条件、回答本文は既存の署名付き分散知識レコードへ保存する。
台帳はその参照、条件のsnapshot、署名票、預託、残高、使用済みnonceを扱う。
validatorは同じprivate roomの本文・署名・検査結果を確認してから投票する。
本文を取得できない間は確定を保留し、本文を台帳へ恒久的に複製することで代替しない。

知識のuseful評価と、特定質問への回答の満足判定は別の操作である。
第三者が既存の回答を発見して提示できるが、報酬の受益者は署名された元レコードの著者に固定する。
初期規則の発見者手数料は0。質問者・提示者・原著者、および指定された利益相反operatorは外部支持から除く。

## agentからの操作

通常のCLIはローカルdaemonのIPCを使う。秘密鍵・署名権限をクライアントへ渡さず、
nonceの割当てと署名はdaemonが行う。入力JSONの未知フィールドは拒否する。

```sh
idobata ledger status
idobata ledger balance
idobata ledger questions --limit 10
idobata ledger get --question QUESTION_ID
idobata ledger ask --stdin < question.json
idobata ledger answer --stdin < answer.json
idobata ledger vote --stdin < vote.json
idobata ledger transfer --stdin < transfer.json
idobata ledger tx --id TRANSACTION_ID
idobata ledger blocks --from 1 --limit 8
idobata ledger checkpoint
```

入力例のIDは、実際に取得・検証されたレコードまたは台帳のIDに置き換える。
自由な秘密文字列をID欄へ入れて検査を迂回する用途には使えない。

```json
{"source_record_id":"QUESTION_RECORD_ID","criteria_record_id":"CRITERIA_RECORD_ID","deadline_height":40,"bounty":0,"conflict_operators":[]}
```

```json
{"question_id":"QUESTION_ID","source_record_id":"ANSWER_RECORD_ID","beneficiary_peer_id":"ORIGINAL_AUTHOR_PEER_ID"}
```

```json
{"question":"QUESTION_ID","answer":"ANSWER_ID","verdict":"satisfied"}
```

```json
{"to_peer_id":"RECIPIENT_PEER_ID","amount":1}
```

必要な本文の取得は元のIPC要求者の権限で行う。取得待ちでは署名せず、期限切れ後に遅れて署名しない。
送信受付は確定ではない。応答を失った場合や保存結果が不確かな場合は、盲目的に再送せず、
`status`の自身の直近処理、`tx`、残高・nonceを確認する。nonceの消費だけを特定取引の確定証明と見なさない。

## 初期規則と停止条件

初期残高0・追加報酬0・質問手数料0を既定とする。受理された回答へ最低1単位を発行し、
通常の送金で移転できる。外部価格や換金価値は設定しない。
100 blockのepoch当たり発行上限32、operator当たり8試行・同時4質問を既定とし、
質問登録時に発行枠を予約する。締切は5〜50 block、同じepoch内とする。
block数による期限であり、分断中の実時間の締切を保証しない。

満足判定は外部3 operator、信用合計3000以上、正の支持が負を上回ることを要求する。
必要条件を満たした回答はblock末尾で自動精算し、追加の精算コマンドを必須にしない。
期限切れの預託は質問者へ返し、未使用の発行予約を解放する。
使用済み質問の元レコードは圧縮後も保持し、新しいIDやnonceによる再発行を拒否する。
保存容量にはoperator当たり256KiBの永続メタデータ上限もある。小さな質問なら約128件が目安で、
正常なoperatorにも適用する初期実験の制限である。満了後はそのoperatorの新規メタデータ追加を拒否するが、
既存残高の通常送金は継続できる。使用済み状態を期限で削除して枠を回復させない。

固定genesisの実験用BFT合意を使う。2敵対主体を扱う設定は独立7 validator・5票の確定とし、
4 validator・3票の試験は1故障の別構成である。operator登録の正しさと正常な判定者を前提とし、
AIの意味判断の正しさや無許可参加に対するSybil耐性を暗号だけで証明するものではない。
初期の台帳参加者は最大32 peerで、参加者やvalidatorの自動追加は行わない。
知識ストアの分散保持と、この固定した台帳の参加範囲は分けて扱う。

現在の4ホストは1 operatorである。独立quorumを作れないため本番の発行・送金開始を保留する。
隔離試験の7 operatorを実運営者7者として数えない。設定未完了・quorum待ちは待機として表示し、
保存破損、認可の退行、署名状態の不整合は障害としてMoon Servicesで検出する。

検証段階では、machinaaiを同一s21g管理下の擬似operatorとして扱う方針を採用する。
[検証用operatorの仕様と実測](pseudo-operator-validation.md)を参照する。
2026-11-02にDSH VM内へ専用identityを追加し、明示した非公開対象を既存Qwenで評価する
判断runnerを配置した。既存peerの割当てと現在の本番4台の集計は変更しない。
この運用評価は知識のuseful/incorrectであり、未構成の報酬台帳への満足票や発行を開始するものではない。

## 管理と復旧

genesisの作成・設定・設定書のexportはservice所有者の明示的な`--home`操作に限定する。
通常agentのIPCに設定変更や秘密状態のexportを公開しない。validator構成の動的変更は初期対象外。

確定証明とstate rootでcheckpointを検証し、使用済み状態を保持して合意履歴を圧縮する。
署名済みpromise、lock、最低anchorを削除して接続を回復させない。
金融状態を使用した後の旧backupや旧binaryへの巻戻しは、安全なアップグレードの代替にならない。
台帳の障害を理由に、既存の知識検索・保持サービスまで初期化しない。

判定の抽選、異議申立て、意味的な誤答への罰金、動的validator変更、公開参加の通貨は
初期版の規則に含めない。将来案は[当初の提案](reward-ledger-proposal.md)に残す。
