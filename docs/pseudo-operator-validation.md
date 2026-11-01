# 検証用の擬似operator

2026-11-02に専用peer・判断runner・定期更新・Moon Servicesへの反映を実施した。
既存machinaai peerはs21gのまま保持し、DSH VM内の追加identityをmachinaai-testへ登録する。
実管理者は引き続きs21gの1者であり、擬似operatorを実際の独立主体数へ加算しない。
[peer運用](dsh-peer-operations.md)、[判断runner](dsh-judge-runner.md)、
[監視](dsh-delegation-monitor.md)、[実施した検証](verification.md)を参照する。

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

## 2026-11-01の変更前検証

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

## 2026-11-02の反映結果

反映対象は既存machinaai peerの付け替えではなく、DSH VM内の追加検証peerである。
専用OSサービスが独自identityと状態を持ち、UID2000のagentは専用Unix IPCで操作する。
DSHのホストmount禁止と既存ファイアウォールを維持し、peer通信にはloopback限定の
SSH転送と署名済み公開WSS経路を使う。

専用非公開room `dsh-lab`にはLinux hub、machinaaiホスト、DSH検証peerを登録する。
前二者はs21g、後者はmachinaai-testに束縛し、実管理者は全てs21gと記録する。
3 peerでR3保持を検証するが、2 operatorによる採用・台帳発行を許可する変更は行わない。

判断はDSH環境の既存Qwen relayへツールなしで委任する専用runnerが行う。
DSH headless自体を起動したとか、異なるモデルを独立運営者として認証したとは表示しない。
root管理の明示的ジョブだけをタイマーで処理し、本文内の指示を実行しない。
期限、対象レコードと内容の照合、送信前の永続記録、結果不明時の自動再送禁止を設ける。
ジョブがない場合の待機と、判断の棄権、通信・推論・保存障害を区別する。

Moon Servicesでは既存4 peerの監視と観測窓を維持し、検証peerと判断runnerの状態を
別項目として表示する。synthetic=true、common_controller=s21g、実operator数への寄与0を
明記し、DSHと同じQwenを使う判断runnerであることを示す。
専用peerは通常のDSH権限からCLI/IPCを使える。4件の初期レコードについて各peerで
3 keeper・ACK3・複製完了を確認し、公開feedへ出ていないことを確認した。

正答はuseful、誤答と採点指示を混ぜた誤答はnot_usefulとなり、SDKにはuseful/incorrectを適用した。
初期のモデル出力形式拒否1件は送信前に止め、履歴・失敗数を保持した。
モデルへIDのコピーを要求する方式をやめ、version/judgment/reasonだけを返させる。
対象IDと内容digestはrunnerが固定し、保存した決定と適用時に再照合する。

認可をepoch1から2へ更新し、3 peerとrunnerの証明書の一致を確認した。
更新は実際にrunner.lockを持つguestプロセス内で行い、先行永続markerで途中停止を検知する。
途中停止時は評価を遮断し、同じepochの再整合で復旧する。通常更新と旧roomの更新は
共通の管理lockで直列化する。更新後の新しい対象も常設timerが推論・評価を完了した。
