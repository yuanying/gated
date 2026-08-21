# 0002. 認可モデル: NetworkRole と NetworkRoleBinding

- Date: 2026-08-21
- Status: Accepted

## Context

これまでアクセス制限は ingress-nginx の BASIC 認証アノテーションで行っていた。保護したい Ingress に `auth-type` / `auth-secret` / `auth-realm` の3つを書き、パスワードハッシュを Secret に置く方式である。

この方式には2つの問題がある。

1つは、権限が Ingress リソースに埋め込まれていること。「誰がこのサービスを使えるか」は Ingress を書いた人ではなく運用者が決めることであり、経路の定義とは変更のタイミングも理由も異なる。にもかかわらず同じリソースに同居しているため、権限を変えるたびにアプリケーションの manifest を触ることになる。Helm chart や上流が配布する manifest をそのまま使いたい場合はさらに厄介で、kustomize のパッチで無理やりアノテーションを注入することになる。

もう1つは、BASIC 認証では「誰が」を表現できないこと。パスワードを知っているかどうかしか分からず、アクセスした人物を識別できない。共有パスワードの入れ替えも全利用者に影響する。

そこで権限を Ingress の外に出し、Kubernetes の RBAC と同じ語彙で表現したい。

## Decision

権限を表す2つの CRD を `gate.unstable.cloud` に定義する。RBAC の Role / RoleBinding と同じ分離である。

| リソース | 役割 |
|---|---|
| `NetworkRole` | 何に対して何ができるかを定義する。保護対象と、許す操作の集合 |
| `NetworkRoleBinding` | `NetworkRole` を主体（subject）に結び付ける |

分離しているのは、同じ権限セットを複数の相手に与えたり、同じ相手に複数の権限を与えたりを、それぞれ独立に書けるようにするためである。

### 保護対象の指定

`NetworkRole` は保護対象を **Ingress の名前参照**（`targetRef`）で指定する。namespace と name で対象の Ingress を名指しする。

ホスト名やパスを直接書く方式も検討したが採らなかった。Ingress 側でホスト名を変更したときに `NetworkRole` の修正を忘れると、保護されているはずの URL が無防備になる。名前参照ならホスト名の変更に自動的に追従する。

この形は Gateway API の `ReferenceGrant` に近く、将来 HTTPRoute を保護対象に加えるときも `targetRef` の `kind` を増やすだけで済む。

### 認可の粒度

`NetworkRole` の `rules` はパスと HTTP メソッドの組で権限を表現する。RBAC における resource と verb に相当する。

これにより「未認証の相手には GET だけ許し、書き込みは自分だけ」といった権限が表現できる。BASIC 認証では全か無かしか表現できなかったものである。

### 主体の語彙

`NetworkRoleBinding` の `subjects` には次を書ける。識別子の形式は llm-wiki の `_access.yml` と揃える。

| 主体 | 意味 |
|---|---|
| `github:<login名>` | GitHub の特定アカウント |
| `google:<メールアドレス>` | Google の特定アカウント |
| `system:authenticated` | ログイン済みであれば誰でも |
| `system:unauthenticated` | 未ログインを含む誰でも |

`system:` で始まる2つは RBAC から語彙を借りた仮想的な主体である。「誰でも読めるが書けるのは自分だけ」は、GET のみを許す `NetworkRole` を `system:unauthenticated` に、全メソッドを許す `NetworkRole` を `github:yuanying` に、それぞれ束ねることで表現する。

グループは当面導入しない。実質的な利用者が一人であり、メンバー集合を使い回す必要が出ていないためである。必要になった時点で `NetworkGroup` CRD を追加し、`subjects` に `kind: Group` を足す。

### 拒否されたときの挙動

未ログインの主体で拒否された場合、即座に 403 を返さない。ログインへ誘導し、認証後の主体で改めて判定する。それでも拒否されたときに 403 を返す。

RBAC の素直な解釈では未認証で権限が無ければ拒否だが、Web UI として使う以上「ログインすれば通れるのにログイン画面が出ない」のは受け入れがたい。

ただしリダイレクトは相手がブラウザである場合に限る。`Accept` ヘッダが HTML を求めていない場合はリダイレクトせず、401 と `WWW-Authenticate` を返す。API クライアントを 302 でログイン画面に飛ばしても意味がないためである。

### 参照されていない Ingress の扱い

どの `NetworkRole` からも参照されていない Ingress は、認証なしで素通しする（fail-open）。

llm-wiki では「visibility を書かないページは private」という fail-closed を採ったが、ここでは逆にする。llm-wiki のページは大半が非公開で公開が例外だったのに対し、この Ingress 群は大半が公開サイトで保護が例外である。既定を拒否にすると、公開したい全 Ingress に「全員に許可する」という無意味なポリシーを書くことになり、ポリシーの存在自体が意味を持たなくなる。

## Consequences

権限がアプリケーションの manifest から完全に分離される。上流が配布する Ingress をそのまま使いながら、権限だけを別リソースで後付けできる。権限の変更もアプリケーションに触れずに済む。

「誰が」が識別できるようになる。共有パスワードではなく個人のアカウントで認証されるため、アクセスを個人単位で剥がせる。

判定はコントローラのプロセス内で完結する。CRD の内容は informer でキャッシュしているため、リクエストごとに API サーバへ問い合わせる必要がない。標準の RBAC に載せて `SubjectAccessReview` で判定する案も検討したが、全 HTTP リクエストで API サーバを叩くことになり、API サーバが落ちたときにトラフィックも止まる。この結合は避けたい。

代償として、`kubectl auth can-i` は使えない。権限が実際にどう効いているかを確かめる手段を自分で用意する必要がある。

fail-open を選んだため、`targetRef` の namespace や name を打ち間違えると、保護したつもりの Ingress が無防備になる。この失敗は静かに起きるので、`NetworkRole` の `status` に「解決できた対象 Ingress」を書き戻し、解決できなかった参照を検知できるようにしなければならない。

パスとメソッドまで見る粒度を選んだため、複数の `NetworkRole` が同じ Ingress の重なるパスに対して異なる権限を与える状況が起こりうる。RBAC と同じく**許可の和**とし、拒否のルールは持たない。どれか1つでも許せば通る、という単純な規則にすることで、評価順序に依存しない判定にする。

## 関連 ADR

- [[0001-self-built-ingress-controller]] — Ingress の外に権限を出すという方針
- [[0003-authentication-and-session]] — 主体をどう識別するか
- [[0004-access-token-for-non-browser-clients]] — ブラウザ以外の主体
- [[0007-test-strategy]] — 判定を純関数として検証する
