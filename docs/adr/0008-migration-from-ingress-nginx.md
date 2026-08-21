# 0008. ingress-nginx からの移行

- Date: 2026-08-21
- Status: Accepted

## Context

移行対象は fleet-infra が管理する自宅クラスターであり、Ingress は14個ある。うち8個が BASIC 認証で保護されており、残りは公開サイトである。証明書はすべて cert-manager が Let's Encrypt から取得している。

トラフィックの入口は2系統ある。

| 系統 | 経路 |
|---|---|
| IPv4 | ルーターが持つ単一のグローバル IPv4 の 80 / 443 を、MetalLB が払い出す1つのアドレスへポートフォワードしている |
| IPv6 | MetalLB が払い出すグローバル IPv6 アドレスへ NAT を挟まず直接到達する |

ここに制約がある。グローバル IPv4 は1つしかなく、80 / 443 は1つの内部アドレスにしか転送できない。したがって IPv4 経路については、新旧2つの Ingress Controller を外から同時に到達可能な状態にできない。

一方 IPv6 は NAT を挟まないため、別アドレスを与えれば新旧の並行稼働が可能である。実際、fleet-infra の test オーバーレイは既に IPv6 の別アドレスへパッチする形で運用されている。

なお ingress-nginx がサポートを終える時期が決まっている以上、移行には期限がある。

## Decision

test クラスターで検証を完了させたのち、prod では一括で切り替える。

### 段階

1. **test クラスターでの検証** — test オーバーレイに gated をデプロイし、証明書の発行、Identity Provider によるログイン、`NetworkRole` による認可、`AccessToken` による非ブラウザ経路を一通り確認する。test は IPv6 単独で運用されているため、実際の Let's Encrypt と実際の Identity Provider に対して検証できる
2. **prod の manifest 準備** — 14個の Ingress の `ingressClassName` を gated のものへ変更し、BASIC 認証のアノテーション8箇所を `NetworkRole` / `NetworkRoleBinding` に置き換える。`kubernetes.io/tls-acme` アノテーションは削除する（gated は `spec.tls` を見るため不要）
3. **切り替え** — MetalLB が払い出す IPv4 と IPv6 のアドレスを gated の Service へ付け替える
4. **撤去** — 安定を確認したのち ingress-nginx と cert-manager を削除する

### 切り戻し

切り戻しは MetalLB のアドレスを ingress-nginx の Service へ戻し、Ingress の `ingressClassName` を戻すことで行う。そのため ingress-nginx と cert-manager は切り替え後もしばらく残す。

証明書は Secret に同じ名前・同じ形式で保存される（ADR 0005）ため、どちらのコントローラも同じ Secret を読める。切り戻しの際に証明書を取り直す必要はない。

### 並行稼働を採らない理由

prod で IPv6 の別アドレスを使えば新旧の並行稼働は技術的に可能であり、Ingress を1つずつ移す段階的な移行もできる。しかし IPv4 経路の到達性だけはどうやっても事前に検証できず、最後に一度は「切り替えてみるまで分からない」瞬間が残る。段階移行はその瞬間の回数を増やしはしないが、移行期間中ずっと2つのコントローラを面倒見ることになる。

自宅クラスターは短時間の停止が許容できる。検証の場として test クラスターが既にあり、そこで実際の Let's Encrypt と実際の Identity Provider に対して確認できる以上、prod で並行稼働させて得られるものは IPv4 到達性以外にほとんどない。

## Consequences

移行期間中に2つの Ingress Controller を運用する負担がない。手順が単純で、切り戻しも MetalLB のアドレスを戻すだけである。

既存の Ingress は `ingressClassName` の変更だけで移行できる。`spec.tls` をそのまま使い（ADR 0005）、証明書の Secret 名も変わらない。アノテーションの追加は不要である。

一方で、prod 固有の問題は切り替え後にしか現れない。IPv4 からの到達性、prod の実トラフィック量、prod のバックエンドが持つ癖（長時間接続、大きなリクエストボディ、WebSocket）はいずれも切り替えて初めて分かる。切り替えは時間に余裕のあるときに行い、切り戻しの手順を事前に確認しておく必要がある。

BASIC 認証から `NetworkRole` への置き換えは、単なる書き換えではなく認証方式そのものの変更である。8箇所それぞれについて、ブラウザからアクセスされるのか、機械からアクセスされるのかを確認し、後者には `AccessToken`（ADR 0004）を用意する必要がある。特に Docker registry は `docker login` の資格情報の入れ替えが伴う。

cert-manager の撤去にあたり、`cert-manager.io/inject-ca-from` を使っている箇所の代替を決める必要がある。gated は CA の注入機能を持たない（ADR 0005）。

`kubernetes.io/tls-acme` アノテーションを削除しない場合でも gated は無視するだけで害はないが、cert-manager がまだ動いている間は cert-manager がそれを拾って発行を試みる。切り替えの前後で二重に発行が走らないよう、撤去の順序に注意する。

## 関連 ADR

- [[0002-authorization-model]] — BASIC 認証の置き換え先
- [[0004-access-token-for-non-browser-clients]] — Docker registry の移行
- [[0005-certificate-issuance]] — cert-manager の置き換え
- [[0007-test-strategy]] — test クラスターでの検証の位置づけ
