# 0010. CRD スキーマでどこまで弾くか

- Date: 2026-08-21
- Status: Accepted

## Context

ADR 0002 は、どの `NetworkRole` からも参照されていない Ingress を素通しにすると決めた（fail-open）。この選択には副作用がある。権限の宣言を書き間違えた結果として「何も保護していない `NetworkRole`」が生まれた場合、それは拒否ではなく素通しとして現れる。失敗が静かである。

同じ性質は主体の綴りにもある。`github:octocat` を `octocat` と書いた `NetworkRoleBinding` は、誰にも一致しない権限として存在し続ける。こちらは見えなくなる方向の失敗なので実害は小さいが、原因の分かりにくさは同じである。

CRD のスキーマは、この種の誤りを admission の時点で弾ける唯一の場所である。どこまで弾かせるかを決める必要がある。

## Decision

書き間違いと区別がつかない値は、すべて apiserver に弾かせる。

### 語彙をスキーマに書く

主体の綴り、パスの語彙、HTTP メソッドは、いずれもパターンまたは enum としてスキーマに書く。パスの語彙は RBAC の `nonResourceURLs` に合わせ、完全一致・末尾のワイルドカードによる前方一致・`*` 単独の3つだけを受け付ける。途中にワイルドカードを含むパスは、前方一致として黙って解釈するのではなく拒否する。

### 対象の kind は現に扱えるものだけ

`targetRef` の `group` と `kind` は、いま解決できる `networking.k8s.io/Ingress` だけを許す enum とする。ADR 0001 と 0002 は将来 HTTPRoute を対象に加えることを想定しているが、それは enum を広げる変更であって、参照の形を変える話ではない。

いま扱えない kind を書けてしまうと、その `NetworkRole` は対象を解決できず、fail-open により保護したつもりの Ingress が素通しになる。将来の拡張性のために現在の穴を許す取引はしない。

### `AccessToken` に `system:` 主体を許さない

`AccessToken` の `spec.subject` は `github:` と `google:` のみを受け付ける。トークンは誰かに属している必要があり、「誰でも」として振る舞うトークンは、そのトークンを持つ者に匿名アクセスと同じものしか与えない。意味を持たない設定は書けないほうがよい。

### スキーマでは既定値を埋めない範囲

`targetRef.namespace` と `AccessToken` の `spec.secretName` には CRD の default を置かない。どちらも「省略時はリソース自身の namespace / 名前」という規則であり、これはリソースごとに違う値になるため、スキーマの default では表現できない。コントローラ側の解決規則として実装する。

一方 `targetRef` の `group` / `kind` と subject の `kind` は、どのリソースでも同じ値になるので default を置く。省略して書けることと、読み返したときに何を指しているか分かることの両方が成り立つ。

## Consequences

権限の宣言の誤りが `kubectl apply` の時点で分かる。fail-open が静かな穴になる経路のうち、綴りと語彙に起因するものは admission で塞がれる。残るのは「実在するが意図と違う Ingress を指している」場合であり、これは `status.resolvedTargets`（ADR 0002）で確認する。

代償として、スキーマが gated の実装と密に結び付く。HTTP メソッドを追加したり、新しい Identity Provider を足したりするたびに CRD を再生成して適用する必要がある。gated 自身がその CRD の唯一の利用者であるため、この結合は受け入れられる範囲だと判断する。

パターンによる検証は正規表現の表現力までしか届かない。`google:` の主体はメールアドレスの形をしていることしか確かめられず、それが実在するかどうかは認証時に分かる。スキーマは書き間違いを弾くためのものであって、正しさを保証するものではない。

## 関連 ADR

- [[0002-authorization-model]] — fail-open と主体の語彙
- [[0004-access-token-for-non-browser-clients]] — トークンが属する主体
- [[0007-test-strategy]] — スキーマを envtest で検証する方針
