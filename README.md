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

## Status

設計中。実装はこれから。
