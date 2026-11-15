# 0041. 名前空間のラベルで、その名前空間の Ingress を既定で閉じる

- Date: 2026-11-15
- Status: Accepted

## Context

ADR 0002 の Decision 項「参照されていない Ingress の扱い」は、どの `NetworkRole` からも参照されていない Ingress を認証なしで素通しにする（fail-open）と決めた。Ingress の大半は公開を目的としたものであり、既定を拒否にすると公開したいすべての Ingress に「全員に許す」ポリシーが要る、というのがその理由である。

この理由は、Ingress を書くのが gated の利用者をよく知る運用者である間は成り立つ。成り立たなくなるのは、信用の低い書き手に Ingress を書かせる名前空間を作るときである。例として、エージェントが自分用のアプリを自由に置ける名前空間（`penelope-lab` のような）を考える。そこではエージェントが Ingress も `NetworkRole` も書く。`NetworkRole` を付け忘れた Ingress は、そのままインターネットに認証なしで開く。

この付け忘れは、いまの gated では見つけられない。gated が status・Event・メトリクスで知らせるのは「`targetRef` が解決しない `NetworkRole`」だけであり（ADR 0017、ADR 0031）、`NetworkRole` がそもそも無い Ingress は、正しく公開されている Ingress と区別が付かない。Kubernetes の ValidatingAdmissionPolicy のような入場時の検査でも防げない。入場時の検査は書かれようとしている 1 つのオブジェクトしか見られず、「この Ingress を指す `NetworkRole` が別にあるか」は問えないからである。

守りたいのは「信用の低い書き手が作った Ingress」である。その書き手は、Kubernetes の RBAC によって特定の名前空間の中に閉じ込められている。したがって、既定を閉じる単位を名前空間にすれば、守りたい範囲と境目が一致する。

## Decision

### 適用範囲

ラベル `gate.unstable.cloud/fail-closed` の値が `"true"` の名前空間（以下、閉じた名前空間）にある Ingress だけを対象にする。ラベルが無い、または値が `"true"` 以外の名前空間の Ingress は、ADR 0002 の Decision 項「参照されていない Ingress の扱い」のとおり fail-open のままにする。ADR 0002 は置き換えない。

ラベルの値は `"true"` だけを意味のある値とする。`"True"` や `"yes"` を閉じる側に読むと、何を書けば閉じるのかが gated の実装に依存する。値を 1 つに決めれば、名前空間を書く側（クラスターの配置）がそれを検査できる。

### 閉じた名前空間の Ingress は、それを指す NetworkRole が無ければ誰も通さない

閉じた名前空間の Ingress は、それを `targetRef` で指して解決した `NetworkRole` が 1 つも無い間、「保護されているが、何も許されていない」ものとして扱う。これは ADR 0017 の Decision 項「保護は Role から、許可は Binding から来る」で、束ねられていない `NetworkRole` が与える状態と同じである。新しい状態を作らず、既にある状態に寄せる。

`NetworkRole` が 1 つでも解決すれば、その Ingress は普段どおり評価する。`NetworkRole` がどの名前空間にあるかは問わない。ADR 0002 の Decision 項「書き込み権限が公開範囲の決定権であること」のとおり、`NetworkRole` と `NetworkRoleBinding` を書ける者は、もともと公開範囲を決められる。閉じた名前空間は付け忘れの既定を変えるだけで、その権限は変えない。閉じた名前空間で `NetworkRoleBinding` に `system:unauthenticated` を書けば、その Ingress は誰にでも開く。

`targetRef` が解決しない `NetworkRole` は、閉じた名前空間でも Ingress を保護しない（ADR 0017 の Decision 項「解決できなかった参照は、権限の集合に現れない」）。その結果、Ingress は `NetworkRole` が無い状態と同じになり、閉じる。fail-open の名前空間では打ち間違いが穴を開けるが、閉じた名前空間では閉じたままになる。

### 断り方

断る応答は、ADR 0018 の決定をそのまま使う。判定は Deny であり、ログインへは誘導しない。ログインしても通れる主体が 1 人もいないので、誘導は往復を増やすだけで、ADR 0017 の Consequences が束ねられていない `NetworkRole` について書いた「要ログインではなく拒否として現れる」と同じ形になる。

| 相手 | 応答 |
|---|---|
| ブラウザ（未ログイン・ログイン済みとも） | 403 |
| ブラウザ以外（token の有無を問わない） | 403 |

応答の本文は、ほかの拒否と同じ文面にする。名前空間が閉じていることや、`NetworkRole` が無いことは、インターネットの相手に伝えない。それはクラスターの構成の情報であり、伝えるべき相手は Ingress を書いた側である（後述の観測）。

### 閉じる対象にしない経路

閉じるのは、ルーティングが Ingress を選んだ後の認可だけである。次の経路は認可より前に gated 自身が答えるので、閉じた名前空間でも変わらない。

- 平文のリスナが答える ACME の HTTP-01 の応答と、それ以外の https への転送（ADR 0013、ADR 0015）。証明書は普段どおり発行・更新される。`NetworkRole` が付いた時点で、証明書を待たずに通り始める
- `/__gated/` 以下の予約したパス（ADR 0018、ADR 0020）。ログインと、保護されたホストでの callback を含む

### 名前空間の読みと、変化の反映

gated は Namespace をクラスター全体で読む（get・list・watch）。読むのはラベルだけだが、ラベルを読むための権限はこの 3 つである。Namespace を書く権限は持たない。

名前空間のラベルは、`NetworkRole`・`NetworkRoleBinding`・Ingress と同じ権限のスナップショット（ADR 0017）の材料にする。ラベルが付いた・外れた・名前空間ができた・消えた、のどれでもスナップショットを作り直し、全レプリカが即座に新しい既定で判定する。再起動も起動フラグの変更も要らない。

スナップショットが一度も届いていないレプリカは、ADR 0017 の Decision 項「何も読んでいない間はリクエストを断る」のとおり 503 を返す。名前空間のラベルを読む前に fail-open で答える瞬間は作らない。

### 観測

ADR 0031 に揃え、次の 3 つで見えるようにする。

- アクセスログと `gated_http_requests_total` には、ほかの拒否と同じく、選ばれた Ingress と 403 が残る。メトリクスは増やさない。閉じた状態は穴ではなく、alert で知らせたい「静かな公開」（ADR 0031 の Decision 項「メトリクス」）に当たらないからである
- 拒否のログ（`V(1)`）に、閉じた名前空間で `NetworkRole` が無いために断ったことを書く
- リーダーが、閉じた名前空間にあり gated が受け持つ Ingress のうち、それを指して解決した `NetworkRole` が無いものに、警告の Event を記録する。文面には「この Ingress へのリクエストはすべて拒否される」と、起きている結果を書く（ADR 0017 の Decision 項「解決できなかった参照は status とイベントの両方に出す」と同じ考え方）。Event はその名前空間に書かれるので、Ingress を書いた側が自分の名前空間を見れば理由が分かる

### 前提: ラベルを変えられるのは Namespace を書ける者だけ

この仕組みは、閉じた名前空間で Ingress を書く者が、その名前空間のラベルを変えられないことを前提にする。Kubernetes では、名前空間のラベルを変えるには Namespace オブジェクトそのものへの `update` か `patch` が要る。名前空間の中に閉じた権限（組み込みの `edit` や `admin` の RoleBinding など）は、Namespace オブジェクトを書く権限を含まない。

したがって、Namespace を書ける主体を増やすことは、閉じた名前空間を開く権限を配ることになる。クラスターの配置は、信用の低い書き手に Namespace の書きを与えてはならない。gated はこの前提を確かめない。

### 本 ADR で決定しないこと

- 閉じた名前空間を作るか、どの名前空間に付けるか、Namespace の書きを誰に与えるか（委譲先: gated を配置するクラスターの manifest と、その RBAC）
- 起動フラグでクラスター全体の既定を閉じる仕組み（委譲先: 必要になったときに新しい ADR で決める。ADR 0002 の Decision 項「参照されていない Ingress の扱い」を置き換えることになる）
- ホスト名の単位で既定を閉じる仕組み（委譲先: 同上）

## Consequences

信用の低い書き手に Ingress を書かせる名前空間を、ラベル 1 つで作れるようになる。`NetworkRole` の付け忘れは「インターネットに開く」から「誰にも見えない」に変わり、書いた側は 403 と Event で気付ける。開いたままより気付きやすい失敗である。

gated の起動フラグを変えずに、名前空間ごとに既定を選べる。後から同じ性質の名前空間を足すときも、ラベルを付けるだけで済む。ラベルの無い名前空間の振る舞いは何も変わらない。

gated は Namespace をクラスター全体で読む権限と、その cache を持つことになる。Namespace の数はクラスターの規模に比べて小さく、Secret と違って資格情報を含まないので、これは受け入れる。

ラベルの値の綴りを 1 つに決めたため、`"True"` のような書き間違いは閉じない側に倒れる。閉じたつもりの名前空間が開いたままになるという、防ぎたかったのと同じ形の失敗である。これを防ぐのは名前空間を書く側の検査であり、gated は綴りの違うラベルを警告しない。

閉じた名前空間の中でも、`NetworkRole` と `NetworkRoleBinding` を書ける者は自分の Ingress を誰にでも開ける。この仕組みが防ぐのは付け忘れであって、意図して開くことではない。後者を止めたいなら、その名前空間で `gate.unstable.cloud` の書きを与えないか、入場時の検査で `system:unauthenticated` を断る。

## Alternatives Considered

- **起動フラグでクラスター全体の既定を閉じる。** 公開したい既存のすべての Ingress に「全員に許す」ポリシーが要り、ADR 0002 が退けた形に戻る。
- **ホスト名（ドメイン）の単位で既定を閉じる。** DNS の区切りには合うが、gated の起動フラグを変えて入れ直さなければ範囲を変えられない。守りたい書き手は名前空間で区切られており、ホスト名の区切りとは一致しない。
- **Ingress のアノテーションで閉じる。** 付け忘れを防ぎたい相手が書くオブジェクトに印を付けることになり、付け忘れと同じ形で外される。

## Related ADRs

- [[0002-authorization-model]] — fail-open の既定。本 ADR はその適用範囲を、閉じた名前空間の外に限る
- [[0013-data-plane]] — 平文のリスナが何もしないこと
- [[0015-http01-challenge-sharing]] — 閉じた名前空間でも証明書が発行される経路
- [[0017-authorization-evaluation-and-snapshots]] — 束ねられていない `NetworkRole` と、スナップショットの到着
- [[0018-conveying-a-refusal]] — 403 と予約したパス
- [[0020-where-the-login-lives]] — 予約したパスを答える側
- [[0031-observability]] — 観測の揃え先

## References

- Kubernetes ドキュメント「Using RBAC Authorization」の User-facing roles、および実クラスターの組み込み ClusterRole `admin` の rules（`namespaces` には get・list・watch だけを許すこと）（https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles 、2026-11-15 確認）
- gated の実装 `internal/authz`（`PolicySet.Evaluate`）、`internal/proxy`（`Authorization.Wrap`）、`internal/authn`（`Router`）（リポジトリ、2026-11-15 確認）
