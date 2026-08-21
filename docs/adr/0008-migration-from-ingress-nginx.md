# 0008. ingress-nginx からの移行

- Date: 2026-08-21
- Status: Accepted

## Context

移行対象のクラスターには Ingress が数えるほどある。その一部が BASIC 認証で保護されており、残りは公開サイトである。証明書はすべて cert-manager が Let's Encrypt から取得している。

移行の進め方を決めるにあたって、対象環境には次の制約がある。

**新旧2つの Ingress Controller を、外部から同時に到達可能な状態にできない。** 使えるグローバルアドレスが限られており、80 / 443 は単一の宛先にしか向けられないためである。したがって「新コントローラを別の入口で立てて外形を確認し、納得してから切り替える」という段階移行は取れない。

一方、検証用のクラスターは別に用意されている。ここでは実際の Let's Encrypt と実際の Identity Provider に対して動作を確認できる。

なお ingress-nginx がサポートを終える時期が決まっている以上、移行には期限がある。

## Decision

検証用クラスターで確認を完了させたのち、本番では一括で切り替える。

### 段階

1. **検証用クラスターでの確認** — gated をデプロイし、証明書の発行、Identity Provider によるログイン、`NetworkRole` による認可、`AccessToken` による非ブラウザ経路を一通り確認する。外部サービスは本物を使う
2. **本番の manifest 準備** — 各 Ingress の `ingressClassName` を gated のものへ変更し、BASIC 認証のアノテーションを `NetworkRole` / `NetworkRoleBinding` に置き換える。`kubernetes.io/tls-acme` アノテーションは削除する（gated は `spec.tls` を見るため不要）
3. **切り替え** — ロードバランサが払い出しているアドレスを gated の Service へ付け替える
4. **撤去** — 安定を確認したのち ingress-nginx と cert-manager を削除する

### 切り戻し

切り戻しは、アドレスを ingress-nginx の Service へ戻し、Ingress の `ingressClassName` を戻すことで行う。そのため ingress-nginx と cert-manager は切り替え後もしばらく残す。

証明書は Secret に同じ名前・同じ形式で保存される（ADR 0005）ため、どちらのコントローラも同じ Secret を読める。切り戻しの際に証明書を取り直す必要はない。

### 段階移行を採らない理由

制約は経路によって程度が異なり、一部の経路では新旧の並行稼働が技術的に可能である。しかし最も重要な経路の到達性はどうやっても事前に検証できず、最後に一度は「切り替えてみるまで分からない」瞬間が残る。段階移行はその瞬間の回数を減らしはしないが、移行期間中ずっと2つのコントローラを面倒見ることになる。

対象は短時間の停止が許容できる環境である。検証の場が別にあり、そこで実際の外部サービスに対して確認できる以上、本番で並行稼働させて追加で得られるものはほとんどない。

## Consequences

移行期間中に2つの Ingress Controller を運用する負担がない。手順が単純で、切り戻しもアドレスを戻すだけである。

既存の Ingress は `ingressClassName` の変更だけで移行できる。`spec.tls` をそのまま使い（ADR 0005）、証明書の Secret 名も変わらない。アノテーションの追加は不要である。

一方で、本番固有の問題は切り替え後にしか現れない。外部からの到達性、実トラフィック量、本番のバックエンドが持つ癖（長時間接続、大きなリクエストボディ、WebSocket）はいずれも切り替えて初めて分かる。切り替えは時間に余裕のあるときに行い、切り戻しの手順を事前に確認しておく必要がある。

BASIC 認証から `NetworkRole` への置き換えは、単なる書き換えではなく認証方式そのものの変更である。保護されている箇所それぞれについて、ブラウザからアクセスされるのか機械からアクセスされるのかを確認し、後者には `AccessToken`（ADR 0004）を用意する必要がある。特に Docker registry のようなものは、クライアント側の資格情報の入れ替えが伴う。

cert-manager の撤去にあたり、`cert-manager.io/inject-ca-from` を使っている箇所の代替を決める必要がある。gated は CA の注入機能を持たない（ADR 0005）。

`kubernetes.io/tls-acme` アノテーションを削除しない場合でも gated は無視するだけで害はないが、cert-manager がまだ動いている間は cert-manager がそれを拾って発行を試みる。切り替えの前後で二重に発行が走らないよう、撤去の順序に注意する。

## 関連 ADR

- [[0002-authorization-model]] — BASIC 認証の置き換え先
- [[0004-access-token-for-non-browser-clients]] — 非ブラウザクライアントの移行
- [[0005-certificate-issuance]] — cert-manager の置き換え
- [[0007-test-strategy]] — 検証用クラスターでの確認の位置づけ
