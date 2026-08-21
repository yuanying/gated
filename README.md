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

CRD を適用する。生成物はリポジトリにコミットされているので、そのまま適用できる。

```
kubectl apply -k config/crd
```

担当する IngressClass を作る。`spec.controller` は `gate.unstable.cloud/ingress-controller`
とし、名前は `--ingress-class`（既定 `gated`）と揃える。`ingressClassName` を明示した
Ingress を拾うだけならこのオブジェクトは無くても動くが、`ingressClassName` を持たない
Ingress を既定として拾わせたい場合は必要になる（ADR 0012）。

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

既定値を持つものは、どこで動かしても同じでよい値に限られる。リッスンアドレス
（`--http-addr` / `--https-addr` / `--metrics-addr` / `--health-probe-addr`）、
担当する IngressClass 名（`--ingress-class`、既定 `gated`）、リーダー選出の
タイムアウト（`--leader-election-*`）である。全体は `gated --help` で確認できる。

## 開発

```
make test          # 純関数ユニットテスト。外部依存なし
make test-envtest  # 本物の apiserver と etcd に対する CRD の検証
make generate      # CRD YAML と DeepCopy の再生成
make build         # bin/gated
```

`make test` に乗るのは純関数ユニットテストだけで、それ以外の層は build tag の
後ろにある（ADR 0007）。`make test-envtest` は必要なコントロールプレーンの
バイナリの取得も行う。

## Status

実装中。CRD の定義、起動設定、manager の起動に加えて、Ingress のルーティングと
TLS 終端が入っている。Ingress を適用すれば、`spec.tls` が指す Secret に証明書が
既にある限り HTTPS でバックエンドへ転送される。

証明書の ACME による取得、認証と認可はこれから。それまでは 80 番の
`/.well-known/acme-challenge/` は常に 404 を返す。
