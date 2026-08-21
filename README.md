# gated

ACME による証明書の自動発行と、Identity Provider によるアクセス制御を内蔵した Kubernetes Ingress Controller。

## これは何か

標準の `networking.k8s.io/v1` Ingress を読んで HTTP リクエストをルーティングする Ingress Controller である。加えて次の2つを単一のプロセスに統合している。

- **証明書の自動発行** — Ingress の `spec.tls` を見て Let's Encrypt から証明書を取得・更新する。cert-manager は不要
- **アクセス制御** — GitHub / Google でユーザーを認証し、`NetworkRole` / `NetworkRoleBinding` で「誰がどこにアクセスできるか」を宣言する。BASIC 認証は不要

「誰がアクセスできるか」は Ingress リソースには書かない。Ingress は経路を、`NetworkRole` は権限を、それぞれ独立して表現する。

## 動機

ingress-nginx が deprecated になったため、その置き換えを必要とした。同時に、ingress-nginx + cert-manager + BASIC 認証という3つの仕組みに分かれていた責務を1つにまとめ、認証を Identity Provider ベースへ移した。

設計上の判断とその理由は [docs/adr/](docs/adr/) に記録している。

## 動かし方

### 何を適用するか

必要なものは `config/` にある。CRD も RBAC もリポジトリにコミットされた生成物
なので、そのまま適用できる。

```
kubectl apply -k config/default
```

これで入るのは次のものである。namespace は `gated-system` を使う。

| 種別 | 名前 | 役割 |
|---|---|---|
| CustomResourceDefinition | `networkroles` / `networkrolebindings` / `accesstokens` | 認可とトークンの語彙 |
| ServiceAccount | `gated` | プロセスの身元 |
| ClusterRole / ClusterRoleBinding | `gated` | 後述の権限 |
| Deployment | `gated` | 本体。既定で2レプリカ |
| Service | `gated` | ClusterIP。80 と 443 を待ち受ける |
| IngressClass | `gated` | `spec.controller` は `gate.unstable.cloud/ingress-controller` |

**これだけでは起動しない。** Deployment に書かれているのは、どのクラスターでも
同じ意味になる設定だけである。ACME ディレクトリや中央認証ホストのように特定の
インストールを名指しする設定は既定値を持たないので（ADR 0009）、適用する側が
overlay で足す。足りないまま起動すると、gated は起動を拒否してどのフラグが
足りないかを報告する。足すべきものは次節の表にある。

overlay の書き方の実物は `test/e2e` にある。E2E は `config/manager/deployment.yaml`
をそのまま読み、環境固有のフラグだけを足して適用している。

IngressClass のオブジェクトは、`ingressClassName` を明示した Ingress を拾うだけ
なら無くても動く。`ingressClassName` を持たない Ingress を既定として拾わせたい
場合に必要になる（ADR 0012）。名前は `--ingress-class`（既定 `gated`）と揃える。

外からの入り方は書かれていない。Service は ClusterIP のままである。LoadBalancer
にするのか NodePort にするのかホストポートを使うのかは、gated の性質ではなく
クラスターの性質なので、これも overlay で決める（ADR 0023）。

### 権限

ClusterRole はコードの marker から生成される。`make generate` が
`config/rbac/role.yaml` を書き直すので、手で編集しない（ADR 0011・0023）。

| API グループ | リソース | 与える操作 | 理由 |
|---|---|---|---|
| `networking.k8s.io` | `ingresses` / `ingressclasses` | 読むだけ | ルーティングの入力 |
| （コア） | `services` | 読むだけ | バックエンドの cluster IP を引く |
| （コア） | `secrets` | 読む・作る・更新する | 証明書、ACME アカウント鍵、チャレンジ、署名鍵、トークン |
| （コア） | `events` | 作る・patch する | 発行の失敗や解決できない参照の通知 |
| `coordination.k8s.io` | `leases` | 読む・作る・更新する | リーダー選出 |
| `gate.unstable.cloud` | 3つの CRD | 読むだけ | 認可の判定とトークンの照合 |
| `gate.unstable.cloud` | 3つの CRD の `/status` | 更新する | 解決結果と最終使用日時の書き戻し |

Secret に `delete` は含まれていない。gated は自分が作った Secret も消さない。
手で置いた証明書が消えないことは ADR 0005 の約束であり、権限の側からも塞いである。

Ingress は全 namespace にあり、その `spec.tls` が指す Secret も全 namespace に
あるので、この role は ClusterRole である。

### 起動フラグ

gated 本体は起動フラグで設定する。環境固有の値には既定値が無く、指定を忘れると
起動を拒否してフラグ名と理由を報告する（ADR 0009）。指定が必須なものは次の通り。

| フラグ | 内容 |
|---|---|
| `--acme-directory-url` | 証明書を発行させる ACME ディレクトリの URL |
| `--acme-email` | ACME アカウントに登録する連絡先 |
| `--acme-account-secret` | ACME アカウント鍵を置く Secret（`namespace/name`） |
| `--auth-host` | 中央認証ホストのホスト名（例: `auth.example.com`） |
| `--session-key-secret` | セッション Cookie の署名鍵を置く Secret（`namespace/name`） |
| `--challenge-secret-namespace` | HTTP-01 のチャレンジトークンを置く namespace |
| `--leader-election-namespace` | リーダー選出の Lease を置く namespace |

加えて GitHub と Google のうち少なくとも一方を設定する。どちらも未設定だと、
未ログインのアクセスがログインへ誘導された先が行き止まりになるため、起動を拒否する。

| フラグ | 内容 |
|---|---|
| `--github-client-id` / `--github-client-secret-ref` | GitHub OAuth アプリ（後者は `namespace/name/key`） |
| `--google-client-id` / `--google-client-secret-ref` | Google OAuth クライアント（後者は `namespace/name/key`） |

Identity Provider 側に登録するコールバック URL は、プロバイダごとに1つである。
`https://<--auth-host>/__gated/idp/github/callback` と
`https://<--auth-host>/__gated/idp/google/callback` になる。保護対象のホストを
増やしてもこれは変わらない（ADR 0003）。

既定値を持つものは、どこで動かしても同じでよい値に限られる。リッスンアドレス
（`--http-addr` / `--https-addr` / `--metrics-addr` / `--health-probe-addr`）、
担当する IngressClass 名（`--ingress-class`、既定 `gated`）、リーダー選出の
タイムアウト（`--leader-election-*`）、セッションの寿命（`--session-ttl`、既定
12時間）、Identity Provider のエンドポイント（`--github-base-url` /
`--github-api-url` / `--google-issuer`）である。最後の3つは GitHub Enterprise を
使う場合とテスト用のモック IdP を使う場合にだけ変える（ADR 0021）。全体は
`gated --help` で確認できる。

このうち `--acme-account-secret` / `--session-key-secret` /
`--challenge-secret-namespace` / `--leader-election-namespace` は
`config/manager/deployment.yaml` が既に書いている。どれも「gated 自身が動いて
いる namespace」を指すだけなので、Downward API で解決してある。overlay で足す
必要があるのは、残りの `--acme-directory-url` / `--acme-email` / `--auth-host`
と、Identity Provider の2〜3個である。

中央認証ホストにも TLS 証明書が要るので、`--auth-host` の名前を `spec.tls` に
含む Ingress を1つ用意する。バックエンドは何でもよい。ログインの経路は
ルーティングの手前で処理されるので、そこへ転送されることはない（ADR 0020）。

## 開発

```
make test             # 純関数ユニットテスト。外部依存なし
make test-envtest     # 本物の apiserver と etcd に対する CRD の検証
make test-integration # Pebble とフェイク IdP に対する検証。前者には docker が要る
make test-e2e         # kind クラスターを立てての通し確認。docker が要る
make verify-live      # 本物の ACME ディレクトリに対する検証。明示的に呼んだときだけ
make generate         # CRD YAML・DeepCopy・RBAC の再生成
make build            # bin/gated
make vet              # go vet と gofmt の検査
make lint             # golangci-lint
```

`make test` に乗るのは純関数ユニットテストだけで、それ以外の層は build tag の
後ろにある（ADR 0007）。`make test-envtest` は必要なコントロールプレーンの
バイナリの取得も行う。`make test-integration` は ACME のテストサーバ（Pebble）
とその DNS サーバをコンテナとして起動し、Identity Provider はプロセス内の
フェイクを使う。本物の認証局にも本物の Identity Provider にも接続しない。
docker が使えない環境では ACME の分だけ skip する。

`make test-e2e` はクラスターの生成から破棄までを自分で行う。イメージを組み立て、
kind クラスターを作り、`config/` の manifest と E2E 用の overlay を適用し、
Pebble とモック IdP をクラスター内に置いて、ゴールの4項目に対応するシナリオを
回す（ADR 0024）。数分かかるので日常の開発ループには乗せない。失敗を追いたい
ときは `GATED_E2E_KEEP_CLUSTER=1` を付けるとクラスターが残る。

`make verify-live` だけが本物の外部サービスに触れる。それ以外の層はどれも
外に出ない（ADR 0007）。`go test ./...` にも `make test-e2e` にも混ざらず、
CI では走らない（ADR 0025）。E2E と同じハーネスを使い、違うのは3点だけで、
ACME ディレクトリが実在すること、ホスト名が実際に解決すること、検証が届く先が
公開ポートではなくノード自身のアドレスであることである。

必要な値はすべて環境変数から取る。既定値は持たないので、未設定なら理由を述べて
skip する。

| 環境変数 | 何を渡すか |
|---|---|
| `GATED_LIVE_ZONE` | 検証用のホスト名を作るゾーン |
| `CLOUDFLARE_API_TOKEN` | そのゾーンのレコードを編集できるトークン |
| `GATED_LIVE_IPV6_NETWORK` | インターネットから到達可能な IPv6 を持つ docker network |
| `GATED_LIVE_ACME_EMAIL` | ACME アカウントの連絡先 |
| `GATED_LIVE_ACME_DIRECTORY` | 省略可。既定は Let's Encrypt の staging |
| `GATED_LIVE_ACME_ALLOW_NONSTAGING` | staging 以外を使うときに併せて必要 |
| `GATED_LIVE_KEEP_RECORDS` | 省略可。後始末で DNS レコードを消さない |

ホスト名は実行ごとに変わり、決まった接頭辞で始まる。作ったレコードは成功・失敗の
どちらでも消す。異常終了で消し残した場合は、次の実行が開始時に同じ接頭辞の
レコードを掃除する。

golangci-lint は kind / controller-gen / setup-envtest と同じく `go.mod` の tool
ディレクティブで固定してあるので、別途インストールは要らない（ADR 0011）。
有効にしている linter と、除外している警告とその理由は `.golangci.yml` にある。

## CI

GitHub Actions が、PR と `main` への push のたびに回る。ジョブは上の表の
`make` のターゲットをそのまま呼ぶだけで、CI 専用の入口は無い。赤くなったら
同じターゲットを手元で呼べば再現する（ADR 0026）。

| ジョブ | 呼ぶもの |
|---|---|
| no-live-layer | live 層が CI に入り込んでいないことの検査 |
| vet | `make vet` |
| lint | `make lint` |
| unit | `make test` |
| generate | `make generate` の後に差分が無いこと |
| envtest | `make test-envtest` |
| integration | `make test-integration` |
| e2e | `make test-e2e` |

ジョブの間に依存関係は無く、すべて同時に走る。速い層の結果が E2E の完了を
待たずに返る。

**`make verify-live` は走らない。** 実在の認証局に注文を出し、実在の DNS
ゾーンを書き換える層であり、ADR 0025 が CI の外に置いている。書かなければ
走らない、で済ませていない。`no-live-layer` のジョブが `.github/workflows/`
を全文検索し、live 層の実行か、秘密情報および live 層が読む環境変数への
参照が見つかれば、そこで落ちる。後者が二重目の歯止めになる——live 層は必要な
値をすべて環境変数から取り、既定値を持たないので、渡すものが無ければ何にも
到達せずに skip する（ADR 0025）。三重目として、ワークフローの権限は
読み取りのみである。

CI は秘密情報を一つも要求しない。fork からの PR でも全ジョブがそのまま走る。

Go のバージョンはワークフローに書かず `go.mod` から読む。外部の action は
commit SHA で固定してある。キャッシュは Go のモジュールとビルドのものだけで、
キーは `go.sum` である。テストの結果や「変更が無ければ層ごと skip する」類は
キャッシュしない。キャッシュが壊れた結果として緑になる形を作らないためである。

## 証明書

Ingress の `spec.tls` がそのまま発行の指示になる。`kubernetes.io/tls-acme` の
ようなアノテーションは要らない（ADR 0005）。`spec.tls[].hosts` の証明書を
取得し、`spec.tls[].secretName` の Secret（`kubernetes.io/tls` 型）へ書く。

`secretName` の Secret に有効な証明書が既にあれば取りにいかない。手で置いた
証明書はそのまま使われる。更新は有効期間の 1/3 を切った時点で、ただし最低でも
期限の30日前に始まる（ADR 0014）。更新に失敗しても既存の証明書は書き換えず、
失敗の理由と連続回数は Ingress のイベントとして記録される。

チャレンジは HTTP-01 のみを使う。80 番の `/.well-known/acme-challenge/` は
どのレプリカでも応答できる（ADR 0015）。80 番からバックエンドへ転送する経路は
無く、チャレンジ以外はすべて HTTPS へ 308 で送られる。

## アクセス制御

権限は Ingress の外に置く。`NetworkRole` が「何を守り、何を許すか」を、
`NetworkRoleBinding` が「それを誰に与えるか」を宣言する（ADR 0002）。RBAC の
Role / RoleBinding と同じ分け方で、どちらも namespaced である。

`NetworkRole` は守る対象を Ingress の名前で指す（`spec.targetRef`）。ホスト名では
指さないので、Ingress 側でホスト名が変わっても追従する。`spec.rules` はパスと
HTTP メソッドの組で、パスの語彙は RBAC の `nonResourceURLs` に合わせてある。完全一致、
末尾 `*` による前方一致、`*` 単独の3つだけを受け付ける。

`NetworkRoleBinding` の `subjects` に書けるのは、`github:<login名>` /
`google:<メールアドレス>` / `system:authenticated` / `system:unauthenticated` の4つ
である。綴りはスキーマで検証されるので、書き間違いは `kubectl apply` の時点で弾かれる
（ADR 0010）。

判定の規則は次の通り。

- **どの `NetworkRole` からも参照されない Ingress は素通し**（fail-open）。公開が
  原則で保護が例外だという前提に合わせてある
- 複数の宣言が重なった場合は**許可の和**。拒否の規則は持たず、評価順序に依存しない
- `NetworkRole` を書いて `NetworkRoleBinding` を書かないと、その対象は誰にも開かない。
  保護は role から、許可は binding から来る（ADR 0017）
- 未ログインで許可されず、ログインすれば通りうる場合はログインへ誘導する。ブラウザ
  以外（`Accept` が HTML を求めていない相手）には 302 ではなく 401 と
  `WWW-Authenticate: Basic` を返す。ログイン済みで許可されなければ 403（ADR 0018）

fail-open を選んでいるので、`targetRef` の書き間違いは「保護したつもりのものが
無防備」という静かな失敗になる。これを見えるようにするために、解決結果を
`status.resolvedTargets` に、可否を `TargetResolved` condition に書き戻し、解決
できなければ警告イベントも記録する。`NetworkRoleBinding` の `RoleResolved` も同じ
である。`kubectl describe` で両方が読める。

## 認証

誰であるかは、GitHub か Google でのログインで確定する。ログインの入口は
`--auth-host` で与える**中央認証ホスト**1つに集約されていて、保護対象のホストへ
未ログインでアクセスすると、そこへ送られる（ADR 0003）。

流れは次の通りである。

1. 保護対象ホストが、そのホスト限定の短命な Cookie に乱数を置き、中央認証ホストへ送る
2. 中央認証ホストが Identity Provider とやり取りして、誰であるかを確定させる
3. 中央認証ホストが、30秒だけ有効な署名付きトークンを付けて元のホストへ戻す
4. 元のホストがトークンと手元の乱数を突き合わせ、**そのホスト限定の**セッション Cookie を発行する

3のトークンは URL に乗るが、1で置いた乱数を持つブラウザでしか使えず、使うと乱数が
消えるので二度は使えない（ADR 0020）。戻り先として受け付けるのはルーティング
テーブルにあるホストだけで、それ以外は拒否する（ADR 0018）。

セッション Cookie に入るのは識別子と有効期限だけで、権限は入らない。権限は
リクエストのたびに評価するので、`NetworkRoleBinding` を消せば次のリクエストから
効く（ADR 0003）。Cookie は `HttpOnly` / `Secure` / `SameSite=Lax` が付き、
発行したホストにしか送られない。親ドメインには広げない。

署名鍵は `--session-key-secret` の Secret（`key` エントリ）に置く。無ければ
リーダーが生成して書く。既にあるものは書き換えない。鍵を差し替えると、その
installation の全セッションが一度に無効になる。

Google は OIDC で、ID トークンの `email_verified` が真であることを必ず確認する。
未検証のアドレスを信用すると、そのアドレスを自称する第三者に権限を与えることに
なるためである（ADR 0003）。GitHub は OIDC を提供していないので、OAuth 2.0 の
交換のあと `/user` でアカウント名を得る。

`/__gated/` 以下のパスは gated が予約している。アプリケーションへは転送されない。

## ブラウザを持たないクライアント

`docker push` の途中でブラウザは開けない。ブラウザのリダイレクトを前提にできない
クライアントのために、主体に紐付いた長命のトークンを `AccessToken` で発行する
（ADR 0004）。

トークンの実体を人が書くことはない。`AccessToken` に「どの主体として振る舞うか」を
書くと、コントローラが値を生成して `Opaque` Secret の `token` エントリに書き込み、
その参照を `status.secretRef` に返す。`spec.secretName` を省略すると `AccessToken`
自身の名前が使われる。値の形は `gat_` に続く 32 バイトの乱数で、`gat_` という接頭辞は
漏れたトークンをそれと分かるようにするためのものである。

`spec.subject` に書けるのは `github:<login名>` か `google:<メールアドレス>` だけで、
`system:` の主体は受け付けない。「ログインした誰か」として振る舞うトークンは、
持っている全員に匿名の規則が与えるものを渡すだけで、トークンを必要としない。

受け取り方は2つある。

| 経路 | 用途 |
|---|---|
| `Authorization: Bearer <token>` | `curl` や API クライアント |
| BASIC 認証の**パスワード欄** | `docker login` など BASIC 認証しか話せないクライアント |

**ユーザー名欄は読まない。** 何を入れても構わない。検証していないので、そこに書いた
名前は認証には一切関与しない（ADR 0022）。BASIC 認証の形をしているが、渡している
のは共有パスワードではなく、個人に紐付いた失効可能なトークンである。

トークンで認証されたリクエストは、`AccessToken` が宣言する主体として扱われ、
**ブラウザ経由とまったく同じ規則で判定される**。入口が2つあるだけで、認可の
仕組みは1つである。したがって主体が許可されていなければ 403 になる。

失効させるには `AccessToken` を消す。次のリクエストから通らなくなる。Secret だけを
消した場合はトークンが作り直される。これが値を差し替える唯一の手段でもある
（ダイジェストから元の値は復元できない）。

プロキシは Secret を読まない。照合するのは `status.tokenHash`（トークンの SHA-256）
であって、トークンそのものではない。全 Secret をこのプロセスのメモリに置かない
ためである（ADR 0013）。照合できたトークンはバックエンドへは転送されない。

`status.lastUsedTime` に最終使用日時が記録される。使われなくなったトークンを
見つけるためのもので、書き込みは1分に1回程度に間引かれる。精度はそのぶん粗い。

## 複数レプリカ

複数レプリカで動かせる。レプリカ間で直接やりとりする経路は無く、共有するものは
すべて Secret を通る（ADR 0006）。

| 責務 | 実行するレプリカ |
|---|---|
| Ingress などの watch とルーティングテーブルの構築 | 全レプリカ |
| ルーティング・プロキシ・TLS 終端 | 全レプリカ |
| ログインの受付とセッションの検証 | 全レプリカ |
| HTTP-01 チャレンジへの応答 | 全レプリカ |
| 権限の集合の構築と認可の判定 | 全レプリカ |
| 有効なトークンの集合の構築と照合 | 全レプリカ |
| `AccessToken` の `lastUsedTime` 書き戻し | 全レプリカ |
| ACME による証明書の取得・更新 | リーダーのみ |
| `NetworkRole` / `NetworkRoleBinding` の status 書き戻し | リーダーのみ |
| セッション署名鍵の生成 | リーダーのみ |
| `AccessToken` のトークン生成と Secret への書き込み | リーダーのみ |

リーダーは Lease で選ぶ。既定で有効で、`--leader-election-namespace` が要る。
単一レプリカで動かす場合は `--leader-elect=false` で切れる（ADR 0016）。

リーダーが落ちている間に止まるのは、証明書の取得と status の書き戻しだけである。
既にある証明書は Secret にあり、どのレプリカもそれで TLS を終端できる。認可の判定も
全レプリカが行うので、トラフィックは流れ続ける。後任は Lease が満了した時点で決まる
（ADR 0019）。

## Status

一通り実装が入っている。CRD の定義、起動設定、Ingress のルーティング、TLS 終端、
ACME による証明書の取得と更新、リーダー選出、認可、認証、`AccessToken`、および
gated 自身を動かすための manifest である。

ゴールの4項目は kind 上の E2E（`make test-e2e`）で通しで確かめている。

1. Ingress を適用すると `spec.tls` を見て証明書が発行され、HTTPS でバックエンドへ
   転送される
2. `NetworkRole` / `NetworkRoleBinding` を適用すると、未ログインのアクセスが
   ログインへ誘導され、認証後の主体で認可が判定される。許可される主体は通り、
   許可されない主体は 403 になる
3. `AccessToken` で発行したトークンが `Authorization: Bearer` と BASIC 認証の
   パスワード欄の双方で通る
4. 複数レプリカで動かしても証明書の発行は重複せず、どのレプリカに届いても
   ACME チャレンジに応答できる

未実装なのは、`NetworkGroup`（ADR 0002）、DNS-01 solver（ADR 0005）、
Gateway API の HTTPRoute 対応（ADR 0001）である。いずれも今回の範囲外として
決めたものである。
