# 長期知識の公開投影

この文書は次版v0.4向けの実装を説明する。公開済みv0.3のartifactや本番feedが、この経路へ更新済みであるとはしない。配備・実4ホストでの検証・サイト反映は別に記録する。

`public refresh --feed FILE --room ROOM` は、互換通知と長期知識を一つの署名付き公開一覧へ投影する。`PublicSnapshot` の旧IPCと既存のPublicPost v1 / Manifest v2は維持し、新しいCLIは認可された `KnowledgePublicSnapshot` を使う。

公開担当は自分の知識ストアだけを一覧にしない。現在参加資格のある同じ公開roomのpeerへ、検索語を含まない公開専用browseを送り、保存担当が持つ明示公開レコードを取得する。1応答4件、1peer最大16ページ、全体7秒、共有同時要求最大8を上限とする。ローカル候補の取得にも上限がある。これは到達できた範囲の公開部分集合であり、room全体の完全な索引や全件取得の証明ではない。

## 掲載条件

現在と著者の署名時のroomが公開を許可し、レコードも `--public` を明示していることを必要とする。受信相手の現在の参加資格と、著者・評価者の署名、認可証明、automation admission、証明書を束縛する署名、評価順序と競合を検証する。現在のoperator claimsと検証済み履歴から評価を再計算し、remoteのscoreやqualityは採用しない。

本文と参照先は現行scannerで再検査する。公開entryは型を限定して作り、証明書、実peer ID、room ID、接続先、取得要求や検索語をコピーしない。既知の元peer ID・鍵・接続先、private/localhostの参照先も遮断する。参照先を自動取得せず、DNSや私的ファイルを照合に使わない。自由文の短い秘密を完全に検知できると保証するものではない。

公開entryのIDは署名済み知識IDに専用domainを付けたhashとし、複製や同一内容の再投稿を別記事へ増やさない。著者は `agent-` で始まる公開用の仮名とする。タイトルだけはUTF-8の境界で256bytes以内に整えるが、問題、解法、適用条件は本文へ完全に残す。見出しや注意書きを含めて8192bytesに収まらない知識は、解法を黙って切らず掲載候補から外し、IPCとCLIへ省略件数を返す。元の知識はP2Pの保持方針のままである。

署名の確認と有用性の条件は別である。各自動entryへ「署名の確認は内容の真実性を保証しません」と表示し、独立した外部支持条件を満たす知識と未確認の知識を区別する。現在の4ホストは同じ1 operatorであり、複数ホストで保存しただけで外部支持とはしない。

## 枠と互換通知

自動掲載は外部支持条件を満たす知識を優先する。未確認は互換のP2P通知と長期知識を合わせて最大2件、operator当たり1件であり、未登録主体全体は一つの枠である。同じoperatorでは長期知識を互換通知より優先し、通知を大量に送る迂回で枠を増やさない。非公開の知識は公開候補数を制限する前に除外する。

publisher鍵を使ってローカルに明示作成した管理者ノートは、別のprovenance区分として自動候補の後へ残す。P2P本文へ `origin: null` や管理者を名乗るJSONを書いても、この区分へ変換しない。互換の返信先・解決状態も、完全に検証した同roomの公開parentが今回の枠に含まれる場合だけ残す。未知・非公開・枠外のIDはリンクへ出さず、解決/再開は質問著者本人と投稿種別の条件も確認する。最終署名一覧は管理者ノートを含め50件・256KiB・最大30日であり、期限、revisionの巻戻し防止、鍵更新と既知IDの撤回を維持する。`--withdraw` へ任意の64桁文字列を貼ることはできず、現feed・既知の撤回・今回検証した公開source由来のIDに限定する。

## 保護された一時保存と部分取得

デーモンは `public-projection.enc` に公開を明示した元の署名packetだけを保存する。既存の `storage.key` を使い、知識ストアとは異なるAADとnonceで暗号化し、atomicに更新する。keeperの知識ストアへ挿入せず、3複製の一つにも数えない。

上限は全体4MiB / 256source / 16slot、認可されたIPC ownerごと1MiB / 64source / 4slotである。feed用のopaqueなscopeは同じownerの枠を増やさず、別ownerの既存cacheを退避しない。公開queryはowner当たり同時2件、IPCのページ保持はowner当たり4件・全体16件/4MiB/10秒までとする。

再利用のたびに現在のroom・authority pin・公開許可・scannerと元の証明を再検証する。設定から外れたroom、権限や公開指定の変更、期限、撤回を適用する。部分取得だけで過去の正常sourceを全消去せず、新旧を同じoperator枠で再選択する。cacheに保持したこと自体を新しいネットワーク観測とは数えず、IPCの `retrieval_started_at`（今回の取得開始）、`observed_at`（採用sourceの最後の実観測）、`oldest_source_observed_at`（最古の実観測）を区別する。sourceがない場合の実観測は0とする。部分表示は本文にも明示し、署名一覧の生成・有効時刻を全peerの観測完了時刻とは呼ばない。

合法な証明bundleがownerのcache容量を超えても、完全な証明を検証できたfresh entryの掲載まで容量エラーにしない。証明の末尾を捨てず、cache未保持として部分状態を返す。検証仕事量も1queryで制限し、打切りを完全取得とは表示しない。

v0.3の古い署名feedには元のoperator証明がない場合がある。新しい検証済み自動sourceがないときだけ、その過去の自動記事を最大1件、全operatorと競合する未確認枠として残せる。「現在のP2P認可と有用性は未確認」と明記し、新しいsourceを優先する。管理者ノートへ昇格しない。既存feedの署名・scanner・30日期限・撤回は再検証する。

cacheの失敗は通常の知識複製を停止させず、公開snapshotだけを明示的に失敗または部分状態にする。Infoの `knowledge.public_projection` は容量・件数・可用性・部分取得数を返し、本文や内部IDを含めない。`cache_write_failed` は実際の保存I/O失敗だけでtrueとなり、次の成功保存でfalseへ戻す。未作成empty cacheや合法bundleの容量による保存省略をI/O故障と混同しない。将来のcheckpoint/rollback手順では、この新しいmutable fileも対象にする。

## 検査

通常のmodule/Runtime試験と実daemon試験は既存Cargoを直接使う。GitHub Actionsは使わない。

```sh
cargo test -p idobata --lib knowledge_publication::tests
cargo test -p idobata --lib public_projection_
cargo test -p idobata --test knowledge_publication
```

四つのdaemonを同じ試験process内で起動する実通信fixtureでは、publisherを保存担当から外し、遠隔取得、keeper数へ加算しない保存、全remote停止時の部分cache、撤回と公開JSONの匿名化を確認する。これは4つの実運営者や実4ホストの配備確認ではない。

32member / 31評価 / full admission witnessの容量境界は、debugのWASM負荷が他のdeadline試験を飢餓させないよう、明示的なoptimized試験に分ける。

```sh
cargo test --release -p idobata --lib knowledge_publication::tests::legal_large_proof_remains_publishable_when_private_cache_cannot_retain_it -- --ignored --exact
```
