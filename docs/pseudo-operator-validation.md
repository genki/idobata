# 検証用の擬似operator

2026-11-01の合意により、machinaaiを同一管理者s21g配下の擬似的な別operatorとして
検証に使う方針とする。dshまたはdsh5への判断委任は、実行環境とIPC権限を確認してから行う。
この方針の採用と、常設環境への設定・自動運用の完了を区別する。

## 検証の規則

- 実管理主体はs21gの1者と記録する。検証用operatorを実際の独立運営者数へ加算しない。
- machinaai用の検証identityと保存領域を本番peerから分け、秘密鍵をagentへ渡さない。
- dshとdsh5を別operatorとして二重に数えない。判断担当の違いと管理主体の独立性は別である。
- 擬似operatorは署名付き認可で登録し、信用は通常の上限1000を維持する。
- 2 operatorでは通常検索の採用に必要な外部3群・信用3000を満たさない。
  著者・質問者・回答受益者と同じoperatorの支持を除外し、同一群の複数peerを重複加算しない。
- 台帳合意のf=1/4 validator/3票、f=2/7 validator/5票を弱めない。
  4 validatorを用意しても異なるoperatorが2群だけなら合意を保留する。
- 発行・送金は隔離したexperiment_only台帳の検証単位に限定する。
  利用枠、nonce、使用済み質問、署名履歴を消して検証を通さない。
- 未設定やquorum不足はHold、保存失敗・署名履歴の不整合は障害として区別する。

## 既存実装で保証される範囲

`OperatorClaims`は署名された`bindings`と`credits`を使う。異なる登録名を別群として扱うが、
ホスト・AI・人間・管理者の実際の独立性は推定しない。
`synthetic`、`common_controller`、判断担当の専用フィールドは現行形式に含まれないため、
共通管理者と検証用の区別はこの運用仕様と検証記録で明示する。ソフトで自動証明したとは扱わない。

同一authority配下の既知peerは、roomを変えてもoperatorへの割当てを変更できない。
常設machinaaiの既存鍵はs21gとして履歴を持つため、その鍵をそのまま付け替えない。
別の検証identityを作る場合も、同一authority/operatorの利用枠を別roomでリセットしない。
本番の証明書や履歴を削除したり、別authorityへ置換してこの制限を迂回したりしない。

台帳の通常agent APIは署名をdaemonへ委任するが、評価の意味判断を自動で生成しない。
外部agentの起動・反復実行・方針・IPC認可を整え、実際の判断ログを確認して初めて
「dshへ運用委任済み」と記録できる。CLIが使えることだけでは委任完了ではない。

## 現在の検証

隔離した4 peer / 2 operatorの追加試験4件が成功した。
署名付き評価3件を入れても外部支持は1群・信用1000に集約され、通常検索では採用されない。
2 validatorのgenesisは拒否され、4 validator / 2 operatorではHoldとなり、
提案・投票・timeoutの署名、nonce消費、発行が行われない。
質問者・提示者・受益者の利益相反で全4 peerの満足票を拒否し、発行0を維持した。
未対応の管理主体フィールドや別peerの鍵を使った偽装も拒否した。
これは一時identityによるローカル統合試験であり、dshによる意味判断や実機4台の独立性を証明しない。

実機のdshはmachinaaiのLima VM内で動く。実agentと同じ一般UID・seccompの実行境界では、
idobata CLI、macOSホストのworkspace、ホスト共有IPC、Linux共有IPCは見えていなかった。
dsh5は別のsweethome5実行環境であり、machinaaiのコマンドではない。
したがって、dshへの運用委任とmachinaaiの常設擬似operator化は、現状で完了したとは扱わない。

この検証では常設環境のgenesis、認可、鍵、サービスを変更していない。
結果は[検証記録](verification.md)へ追記する。
