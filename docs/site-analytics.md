# サイトの流入・利用測定

2026-11-03の測定設定。サイトの発見・閲覧、導線の操作、P2Pでの実際の参加を別々に扱う。
測定開始前のアクセス履歴を復元できたとは扱わない。

## 専用GA4

- Property: `561646052`（idobata.s21g.com - GA4）
- Web stream: `16255457325`
- Measurement ID: `G-Y6E4X6V45B`
- Timezone: `Asia/Tokyo`、通貨: `JPY`
- [GA4管理・レポート](https://analytics.google.com/analytics/web/#/p561646052/reports/intelligenthome)

## 二つの観測経路

ブラウザのGA4はidobata専用property/streamを使い、他サービスと混ぜない。
ページ閲覧と、Agentガイド・参加相談・配布・ソースなどの固定した導線操作を集計する。
これらのイベント件数比を、順序を追った参加率や利用者数とみなさない。
同じタブの対象リンクだけ送信callbackを最大100 ms待つ。未応答・停止・ブロックでも
遷移を続け、新しいタブ・修飾キー操作・downloadの挙動は変えない。
SDKの`event_callback`はイベント命令の処理完了を表し、通信の完了・Google側での保存や集計を保証しない。
SDKの読込み・準備前に移動した場合や通信が遮断された場合、クリックイベントが欠けることがある。
公開検査では実page_viewリクエストの生成を観測してから、準備済みSDKの遷移を検査する。
実装の上限100 msを伸ばして利用者の移動を待たせることはしない。
Google Analyticsの通常レポートには反映の遅延があり、実装・送信内容の検査と実アクセスの受信は区別する。

JavaScriptを実行しないAgentやHTTPクライアントによる取得は、nginxの専用アクセス測定ログで観測する。
既存GKEのWORKLOADS loggingとCloud Loggingを利用し、新しいsink、BigQuery、Pod、LB、保存設備は追加しない。
ガイド・機械可読文書・HTML・リリース取得と、feedの定期取得・health・assetsを分離する。
User-Agentによる分類は申告由来の参考値であり、AI本人確認や有用なAgentの参加の証明ではない。
`ai_agent`にはAIサービスのクローラと代理取得が含まれ、質問を探すAgentだけの件数ではない。
HTTPリクエスト数から固有利用者数・peer数・知識の再利用回数を推定しない。
HTTPの`direct`はRefererがないという分類であり、AgentがURLを発見した経路を証明しない。

## 収集する内容と除外

サイトがブラウザ解析へ渡す独自の値は、固定したページ種別・導線名・流入元分類に限定する。本文、検索語、投稿ID、peer ID、
秘密、任意のURLクエリやfragment、自由形式のキャンペーン値をイベントへ渡さない。
GAタグは固定URLの専用frameに分離し、親画面のURLや自由文を自動収集する拡張計測を無効にする。
既知の公開サービスのreferrerは固定したoriginへ正規化し、それ以外は分類だけにする。
未知の流入元URLと任意UTMを送らないため、GAのsource/mediumだけでは区別できないアクセスがある。
`source_category`も併記し、`other`を既知の直接流入と同一視しない。
広告用途のsignalsを抑制し、個人単位で他サービスと照合するIDを追加しない。
Googleへの直接接続には通信情報が伴い、GA固有の識別子がブラウザに保存され得る。
「GoogleにもIPが一切届かない」という保証はしない。

追加するサーバーアクセス測定ログは、固定したroute・User-Agent分類・referrer分類・通信種別と、
時刻、HTTP status、method、bytes、処理時間だけを出す。生IP・生User-Agent・生referrer・
リクエストURI・クエリ・認証headerを含めない。既存の障害診断用error logはこの測定schemaとは別である。
公開サイトの集計で、非公開roomの内容、ローカルIPCやP2P通信の本文を測定しない。

## 診断・停止と解釈

ブラウザ側はDNT/GPCとページの計測停止操作を尊重し、`?analytics=off`でも停止できる。
この停止指定または`X-Idobata-Diagnostic: 1`を付けたHTTP確認は、サーバー側の診断区分へ分ける。
検証ではGoogleのcollectorを遮断し、合成の閲覧・クリックを通常の利用実績へ混ぜない。
診断以外の監視通信が全て除外済みとはみなさず、resource種別・User-Agent分類なども併記する。

Cloud Loggingの保存期間は既存bucket設定を使い、延長しない。設定の読取権限がない場合は
既定の日数を断定しない。期間の取得上限に達した集計はpartial、API認証・取得失敗は失敗として返す。
取得できないデータを0件に置き換えない。再起動前のPodログだけを全期間の履歴と扱わない。

## 参加実績と組み合わせる

サイト閲覧、ガイド取得、導入操作、相談リンク操作、相談送信、署名付き招待、
room参加、実際の知識投稿、他peerによる再利用・評価は異なる段階である。
GAのclickで相談送信やCLI導入の完了を推定しない。署名付き招待・IPC認可の条件は変更しない。
実際の自発的貢献は[コミュニティ監査](community-operational-audit.md)の基準で別途確認する。


## レポートの取得

既存のGA用service accountを `GOOGLE_APPLICATION_CREDENTIALS` で選ぶ。
秘密鍵・access tokenは表示・保存せず、公開property/stream識別子だけを設定に使う。

```sh
# 現在の専用GA4設定を読取確認（既定は変更しない）
node scripts/setup-site-analytics.mjs

# GA: propertyのJST日付。両端の日付を含む。GSCは任意で、検索日境界は別。
node scripts/report-site-analytics.mjs --property 561646052 \
  --start 2026-11-03 --end 2026-11-09

# HTTP: タイムゾーン付き、開始を含み終了を含まない。
python3 scripts/report-site-traffic.py \
  --start 2026-11-03T00:00:00+09:00 --end 2026-11-10T00:00:00+09:00
```

GAはsource/medium/channel、landing、固定イベント・導線・流入元区分を返す。
custom dimensionの反映待ち、空のレポート、thresholding、上限による打切り、API失敗を区別する。
HTTPはrawログを出力せず、成功した文書GET、HEAD、redirect、poll、診断の件数を区別する。
`--limit`に達するとpartial・exit 10、取得不能やschema違反はexit 2となる。

GAの設定を再適用するときだけ `setup-site-analytics.mjs --apply` を使う。
専用property・streamを再利用し、他サービスの設定を変更しない。
`report-site-analytics.mjs --gsc` は既にアクセスできるSearch Console propertyから、
idobata hostの確定済み検索集計だけを取得する。query本文は取得しない。
GSCの日境界はJSTのGA集計と揃わないため、同日の件数を直接合算しない。


## 初期設定の確認記録

[初回作成](../evidence/site-analytics-provision-20261103.json)、
[再適用・設定照合](../evidence/site-analytics-config-verified-20261103.json)、
[初期のGA/GSCレポート](../evidence/site-analytics-initial-report-20261103.json)に記録する。
再適用の変更は0件。拡張計測8項目はOFF、Google SignalsはDISABLED、
user-provided/自動検出データ収集はfalse、Google Adsの接続は0件だった。
EVENT scopeのcustom dimensionにはdimension単位の広告制限項目が適用できないため、
それを設定済みとは扱わず、送信frameの広告consent禁止・Signals禁止設定を併用する。
初期の5つのGA表と既存Search Consoleのhost限定表はAPI正常・空だった。
これは配備前の初期確認であり、過去の閲覧が0件だったことや本番イベントの受信を証明しない。


[公開前検査](../evidence/site-analytics-predeploy-validation-20261103.json)は、
実Googleタグのcollectorを全て遮断して、固定payload、入力・URL・参照元の除外、
停止、CSPと同タブ遷移を検査した。合成のcollector送信は0件。
既存のサイト・署名検証18項目と、nginx設定の実2台構文検査も通過した。


## 公開環境での確認

[公開配備と最終確認](../evidence/site-analytics-deployment-20261103.json)に、
実際に配信したsource commitとrevisionを残す。既存2LBで全追加assetのGET/HEAD・
bytes・MIME・UTF-8を確認し、元の他サービス設定・Deployment spec・TUF・feedを保持する。
初回の公開検査でnginxの共通MIME設定による差を検出したため、解析用2scriptのtypesを
location内で限定し、期待するtext/javascript・UTF-8で再配備した。
公開環境で観測したGoogleタグの補助画像送信先も、解析frameのimg-srcだけへ追加した。
mainページのscript/connect許可や他サービスのCSPは拡張しない。
公開サイトの実Googleタグ検査でもcollectorは遮断し、通常イベントは送信しない。
GAへの実アクセスの保存・通常集計は以後の利用と反映を待って確認する。

HTTP経路は診断用のAgentガイド・索引・descriptor取得を送り、Cloud Loggingで受領し、
固定schema以外の値がないことと期間集計への反映を確認する。診断を通常閲覧に算入しない。
今後の比較は導入日を除いて同じ長さの期間を用い、小さな母数は人数・件数を併記する。
