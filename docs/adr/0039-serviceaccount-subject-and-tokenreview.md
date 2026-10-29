# 0039. ServiceAccount を主体にし、その token を TokenReview で確かめる

- Date: 2026-10-29
- Status: Accepted

## Context

gated が主体を決める入口は2つある。ブラウザのログインで発行するセッション Cookie（ADR 0003）と、`AccessToken` が発行する長命のトークン（ADR 0004）である。どちらも主体は `github:` か `google:` の、人のアカウントである。

クラスターの中で動く機械も、gated の後ろのサービスを呼ぶ。個人アシスタント、リリースの遅れを知らせるジョブ、fraction-agents の呼び出し元などである。いまこれらには、gated の認可を通る手段が2つしかない。人のアカウントに紐付いた `AccessToken` を Secret に置いて使うか、呼ばれる側の Ingress に `NetworkRole` を付けずに素通しにするかである。前者は機械が人を名乗ることになり、どの機械が呼んだのかが残らない。トークンは長命で、漏れたら人として振る舞える。後者は gated の認可を捨てることになる。fraction-agents は後者を選び、呼び出し元の ServiceAccount の token を自前で TokenReview して認証している。

Kubernetes の中で動くものには、既に身元がある。ServiceAccount である。その token は API サーバが発行し、audience と期限を持ち、Pod や ServiceAccount が消えれば通らなくなる。ADR 0004 はこの token を TokenReview で確かめる案を「手元の `docker login` には使いにくい」として退け、「将来クラスター内からのアクセスに必要になれば、主体の種類として追加できる」と書いた。その必要が生じた。

決めることは次のとおりである。主体をどう書くか。どの token を受け付けるか。どう確かめ、どれだけ覚えておくか。受け付けた token と受け付けなかった token をバックエンドへ渡すか。API サーバに頼ることを、ADR 0002 が避けた「API サーバが落ちたらトラフィックも止まる」結合とどう折り合わせるか。

## Decision

### 主体は `system:serviceaccount:<namespace>:<name>`

ServiceAccount の主体は `system:serviceaccount:<namespace>:<name>` と書く。RBAC の RoleBinding と、TokenReview が返す `status.user.username` と同じ文字列である。ADR 0002 の主体の表に加え、`NetworkRoleBinding` の `subjects` に書けるようにする。

同じ文字列にするのは、写し間違いを起こさせないためである。Kubernetes の権限と gated の権限を並べて書くとき、同じ相手が同じ綴りで現れる。TokenReview の答えを加工せずにそのまま主体にできるので、gated が名前を組み立て直す箇所も無い。

CRD のスキーマ（ADR 0010）は、namespace を DNS-1123 label、name を DNS-1123 subdomain の形に限る。namespace や name が欠けたもの、余分な `:` を含むものは入場時に拒否する。

namespace 単位のグループ（`system:serviceaccounts:<namespace>`）は入れない。ADR 0002 の「グループは要るまで入れない」をそのまま当てはめる。いま呼び出し元は数えるほどで、個別に書けば足りる。

ServiceAccount の主体は「ログイン済み」でもある。`system:authenticated` に許された対象には、gated の audience の token を持つ ServiceAccount も入れる。RBAC の `system:authenticated` が ServiceAccount を含むのと同じ意味である。GitHub のアカウントは誰でも作れるので、`system:authenticated` は元から「誰かとして名乗れた者」以上の意味を持っておらず、この追加で意味が弱まることはない。

### `AccessToken` には ServiceAccount を名乗らせない

`AccessToken` の `spec.subject` は、これまでどおり `github:` と `google:` だけを受け付ける。`system:serviceaccount:` も `system:` で始まるので、スキーマが入場時に拒否し、プロキシが集合を組み立てる時点でもう一度捨てる（ADR 0022 の2つ目の錠）。

ServiceAccount の token は短命で、API サーバが発行し、取り消せる。長命の `AccessToken` で ServiceAccount を名乗れると、その性質がすべて失われる。機械が機械として呼ぶ道は、ServiceAccount 自身の token だけにする。

### 受け付けるのは gated の audience の token だけ

gated が受け付ける audience は1つだけで、起動フラグ `--serviceaccount-audience` で指定する。例は `https://auth.example.com` のような中央認証ホストの origin だが、値は運用者が決める。

1つに限るのは、token を「gated に対する資格情報」に閉じ込めるためである。ServiceAccount の token は audience ごとに別に発行できる。fraction-agents を呼ぶための `a2a` の token は fraction-agents のためのもので、gated がそれを受け付ければ、fraction-agents に渡した token で gated の後ろの別のサービスにも入れることになる。gated の audience の token は gated のためだけに発行させる。

既定値は持たせない。audience は「どの gated に宛てた token か」を決める値で、環境ごとに違う（ADR 0009）。ただし未指定でも起動は拒否せず、そのときは ServiceAccount の token を一切受け付けない。Identity Provider と同じく、入口の1つを開くかどうかの選択であり、開かないことは設定の誤りではないからである。既存の環境は、版を上げただけでは何も変わらない。

audience を API サーバ自身の audience（Pod に既定で mount される token の audience）にしてはならない。そうすると、クラスター中のどの Pod も、何もせずに自分の ServiceAccount として gated を通れる。gated はそれを見分けられないので、これは運用者が守る決まりとして書いておく。

### 見分け方と順序

`Authorization: Bearer` の値が `gat_` で始まれば `AccessToken`、JWT の形（`.` で区切られた3つの base64url の断片で、前の2つが JSON のオブジェクト）をしていれば ServiceAccount の token として扱う。`AccessToken` は JWT の形をしていないので、2つの入口が互いの token を読むことは無い。どちらの形でもない値は、gated の知らない資格情報としてそのまま通す。

BASIC 認証のパスワード欄では受け付けない。BASIC の入口は `docker login` のように他の言葉を話せないクライアントのためのもので（ADR 0004）、ServiceAccount の token を使うクライアントは Bearer を話せる。1つのスキームに入口は1つ、という ADR 0022 の形も保たれる。

主体を尋ねる順は、トークン（`AccessToken` と ServiceAccount）が先、Cookie が後のままにする（ADR 0022）。2種類のトークンは形で排他なので、その間の順は結果に影響しない。

### 確かめ方は TokenReview

gated は token の署名を自分では確かめない。`authentication.k8s.io/v1` の TokenReview を作り、`spec.audiences` に gated の audience を1つ指定して、API サーバに尋ねる。返った答えのうち、次をすべて満たすものだけを受け付ける。

| 確かめること | 満たさなければ |
|---|---|
| `status.authenticated` が真 | `rejected` |
| `status.audiences` に gated の audience が含まれる | `wrong_audience` |
| `status.user.username` が `system:serviceaccount:<namespace>:<name>` の形 | `not_serviceaccount` |

`status.audiences` を改めて確かめるのは、audience を扱わない API サーバや認証器は、`spec.audiences` を無視して audience の無い答えを返すからである。audience が返ってこない答えを「通った」と読めば、どの宛先の token でも受け付けることになる。

username の形を確かめるのは、API サーバが ServiceAccount 以外の利用者も認証しうるからである。OIDC や静的なトークンで認証された人が gated の audience を持つ token を作れる構成では、TokenReview はその人の名前を返す。gated がここで受け付けるのは ServiceAccount だけである。人は人の入口から入る。

TokenReview を選んだのは、token が今も有効かを答えられるのが API サーバだけだからである。公開鍵を取ってきて署名と期限を手元で確かめる方法では、token を発行した Pod や ServiceAccount が消えたことが分からない。束縛された token は、それが消えた時点で通らなくなるべきものである。

判定は純関数として切り出す（ADR 0007）。TokenReview を投げる部分は差し替えられる境界にし、その向こうの Kubernetes の型を判定の側に持ち込まない。テストはその境界を偽の API サーバに差し替えて、答えの組み合わせを表で並べる。

TokenReview を作る権限は、gated の ServiceAccount を `system:auth-delegator` の ClusterRole に結ぶ ClusterRoleBinding で与える。API サーバが最初から持っている、まさにこの用途のための ClusterRole である。`make generate` が書き出す ClusterRole に足す形は採らない。生成される ClusterRole は gated の reconciler が読み書きするものの一覧であり、そこに認証の委譲を混ぜると「何のための権限か」が読み取りにくくなる。

### 尋ねる前に、尋ねるまでもないものを断る

TokenReview を投げる前に、token 自身が書いている `aud` と `exp` を、署名を確かめずに読む。`aud` に gated の audience が無いものは `wrong_audience`、`exp` が過ぎたものは `expired` として、API サーバに尋ねずに断る。

これは断るためだけに使い、受け付ける理由には決して使わない。誰も確かめていない主張は、「いいえ」の根拠にしかならない。偽物の token が gated の audience を名乗っても、その先で TokenReview に断られる。

尋ねずに断るのは、gated を通り抜けるだけの token のためである。fraction-agents の `a2a` の token は、gated の後ろの fraction-agents へ毎回 Bearer で届く。それを要求のたびに TokenReview に回せば、答えが変わらないものに API サーバを使い続けることになる。

### 答えは token の SHA-256 をキーに短く覚える

TokenReview の答えは、token の SHA-256 をキーにして、既定で1分覚える。時間は起動フラグ `--serviceaccount-token-ttl` で変えられる。どこで動かしても同じ意味を持つ値なので既定を持たせる（ADR 0009）。API サーバに尋ねるのは、初めて見た token と、覚えた時間が切れた token だけである。

受け付けた答えは、token 自身の `exp` を超えて覚えない。覚えた時間の途中で token の期限が来たら、その時点で `expired` として断る。

断った答え（`rejected`、`wrong_audience`、`not_serviceaccount`）も同じ時間だけ覚える。偽物の token や他の宛先の token を繰り返し送られても、尋ねるのは1分に1回で済む。断った答えは `exp` で縮めない。断った token が後から通るようになることは無い。

API サーバに尋ねられなかったとき（`review_failed`）は覚えない。それは token についての答えではないので、次の要求でもう一度尋ねる。

キーに token そのものではなくダイジェストを使うのは、メモリに「提示すれば通るもの」を置かないためである。ADR 0022 が `AccessToken` のダイジェストだけを持つのと同じ考え方である。

覚える数には上限（4096）を置く。上限に達したら、期限の切れたものを掃いてから入れる。それでも空かなければ、新しい答えは覚えずに捨てる。まだ有効な答えを追い出すと、何も変わったことをしていない呼び出し元に TokenReview の待ち時間を押し付けることになるからである。毎回新しい偽物の token を送られても、メモリは際限なく増えない。

覚えるのはレプリカごとで、レプリカ間で共有しない（ADR 0006）。答えは API サーバから取り直せるので、共有する理由が無い。レプリカが入れ替わった直後は、そのレプリカにとってすべての token が初めて見るものになる。

### API サーバが落ちても、覚えた token と他の入口は止めない

TokenReview の待ち時間は1件あたり最大5秒とする。答えが無ければ、その token は提示されなかったものとして扱う。主体は決まらず、未ログインとして判定される。

API サーバが落ちている間も、覚えている token は覚えた時間が切れるまで通る。セッション Cookie と `AccessToken` は API サーバに尋ねないので、何も変わらない。止まるのは、覚えた時間の切れた ServiceAccount の token と、初めて見る ServiceAccount の token だけである。

覚えた時間を障害の間だけ延ばすことはしない。延ばせば、障害の間に消された ServiceAccount が通り続ける。障害がいつ終わるかも gated には分からない。

ADR 0002 は認可を `SubjectAccessReview` に載せる案を、全リクエストで API サーバを叩き、API サーバが落ちればトラフィックも止まるとして退けた。この決定はその結合を作らない。尋ねるのは認可ではなく認証で、尋ねるのは ServiceAccount の token だけ、それも1分に1回である。判定は従来どおりプロセスの中で `NetworkRole` と `NetworkRoleBinding` に対して行う。

ServiceAccount の入口は、レプリカが ready になる条件を増やさない。読み込んでおくべき状態を持たず、何も覚えていないレプリカは尋ねるだけだからである。

### 受け付けた token は落とし、主体を `Gated-Assertion` で伝える

受け付けた token は `Authorization` ヘッダごと落としてから転送する（ADR 0022）。gated に宛てた資格情報であり、バックエンドに渡すと、バックエンドがそれを持って gated の後ろの他のサービスへその ServiceAccount として入れる。

主体が決まるので、`Gated-Assertion`（ADR 0034）を付ける。`sub` は `system:serviceaccount:<namespace>:<name>` である。入口が増えても、バックエンドが受け取るものは変わらない。入口は3つ、仕組みは1つである。

### 受け付けなかった token はそのまま転送する

`wrong_audience`・`expired`・`rejected`・`not_serviceaccount`・`review_failed` のどれであっても、`Authorization` ヘッダには触らずにそのまま転送する。主体は決まらず、未ログインとして判定される。ADR 0022 の「gated が消費しなかったものは gated のものではない」をそのまま当てはめる。

fraction-agents が自分の audience の token を自前で確かめ続けられるのは、このためである。gated は自分の audience の token だけを自分のものとして扱い、それ以外には手を付けない。

断った理由はログとメトリクスに出す。ログは `V(1)` で理由と、TokenReview が返した説明（`status.error`）と username を書く。`a2a` の token のように、通り抜けるだけの token は要求ごとに断られるので、既定のログに出すと埋もれる。API サーバに尋ねられなかったことだけは運用の問題なので、既定のログにエラーとして出す。**token の値はどのログにも書かない。**

### メトリクス

| 名前 | 種類 | ラベル |
|---|---|---|
| `gated_serviceaccount_tokens_total` | counter | `result`（`accepted` / `wrong_audience` / `expired` / `rejected` / `not_serviceaccount` / `review_failed`） |
| `gated_serviceaccount_token_reviews_total` | counter | `result`（`authenticated` / `unauthenticated` / `error`） |

前者は ServiceAccount の token が提示されるたびに1つ数える。覚えた答えで済ませたものも数える。後者は API サーバに実際に尋ねた回数で、API サーバへの負荷と、覚えておく仕組みが効いているかを見るためのものである。

ラベルに ServiceAccount の名前は入れない。主体はアクセスログの仕事であり、メトリクスのラベルにしない（ADR 0031）。

### 退けた案

**公開鍵で署名を手元で確かめる。** API サーバの OIDC discovery から公開鍵を取ってきて、JWT の署名と `aud` と `exp` を gated が確かめる。API サーバへの問い合わせは鍵の取得だけで済む。しかし、token を発行した Pod や ServiceAccount が消えたことが分からない。束縛された token の失効は、API サーバが自分の記録と突き合わせて初めて効く。

**覚えずに毎回尋ねる。** 答えはいつも新しい。しかし ServiceAccount の token を使う要求のすべてで API サーバを待つことになり、API サーバが落ちれば ServiceAccount の要求はすべて止まる。

**複数の audience を受け付ける。** 移行中の `a2a` の token もそのまま gated を通せる。しかしそれは、fraction-agents に渡した token で gated の後ろの全サービスに入れることを意味する。audience を分けた意味が無くなる。

**受け付けなかった token を落とす。** バックエンドへ届く資格情報が減る。しかし自前で token を確かめているバックエンドが動かなくなる。gated が消費しないものを gated が捨てる理由は無い。

**namespace 単位の主体を入れる。** `system:serviceaccounts:<namespace>` で、ある namespace の ServiceAccount をまとめて許せる。いまは要らない。要ったときに足しても、既存の主体の意味は変わらない。

## Consequences

クラスターの中の機械が、人のアカウントを借りずに、自分の ServiceAccount として gated の認可を通れるようになる。誰が呼んだかはアクセスログの主体と `Gated-Assertion` の `sub` に残り、`NetworkRoleBinding` で ServiceAccount ごとに許したり外したりできる。

呼ぶ側は、gated の audience の token を projected volume か TokenRequest で手に入れ、Bearer で付けるだけでよい。token の更新は kubelet がする。長命の秘密を Secret に置く必要が無くなる。

運用者が用意するものは、`--serviceaccount-audience` と、gated の ServiceAccount を `system:auth-delegator` に結ぶ ClusterRoleBinding である。後者は `config/rbac` に入っている。

ServiceAccount を消しても、gated が覚えている間（既定で最大1分）は、その token が通り続ける。token の期限はもっと長いので、これは失効を早めこそすれ遅らせはしないが、即時ではない。

初めて見る token を持つ要求は、TokenReview の分だけ遅くなる。同じ token の2回目以降は、覚えている間は遅くならない。

API サーバが落ちている間、覚えた時間の切れた ServiceAccount の要求は未ログインとして扱われ、守られた対象では 401 か 403 になる。ブラウザと `AccessToken` の要求には影響しない。

偽物の token を送り続ける相手は、gated に TokenReview を1分に1回、token の種類の数だけ投げさせられる。断った答えを覚えるので同じ token の繰り返しは効かず、覚える数に上限があるのでメモリも増え続けないが、毎回違う偽物を送られれば、そのたびに API サーバへの問い合わせが1つ増える。gated の audience を名乗る偽物に限られるのは、尋ねる前の確認が他の audience の token を落とすからである。

`system:authenticated` の意味に、gated の audience の token を持つ ServiceAccount が加わる。既存の `system:authenticated` への許可は、そうした ServiceAccount にも開く。

## 関連 ADR

- [[0002-authorization-model]] — 主体の語彙、グループを入れないこと、API サーバとの結合を避けること
- [[0004-access-token-for-non-browser-clients]] — 入口は複数、仕組みは1つ。ServiceAccount を将来の主体として残したこと
- [[0006-high-availability]] — レプリカ間で状態を共有しないこと
- [[0007-test-strategy]] — 判定を純関数として検証すること
- [[0009-startup-configuration]] — 環境固有の値に既定を持たせないこと
- [[0010-crd-schema-strictness]] — 主体の綴りをスキーマで縛ること
- [[0022-presenting-and-checking-a-token]] — 受け取りの順、照合した資格情報を落とし、知らないものは通すこと
- [[0031-observability]] — メトリクスのラベルに主体を入れないこと
- [[0034-conveying-the-subject-to-the-backend]] — 主体を署名付きでバックエンドに伝えること
