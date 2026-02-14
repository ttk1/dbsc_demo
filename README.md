# DBSC Demo

[Device Bound Session Credentials (DBSC)](https://developer.chrome.com/docs/privacy-security/dbsc) の動作を確認するためのデモアプリケーション。

- 仕様: https://www.w3.org/TR/dbsc/
- 仕様 日本語翻訳: [DBSC仕様書_日本語翻訳.md](DBSC仕様書_日本語翻訳.md) (Claude AI による翻訳・参考用)

DBSC はセッション Cookie を TPM に紐づいた鍵ペアでデバイスにバインドする Chrome の機能。Cookie が盗まれても別のデバイスからはセッションをリフレッシュできないため、Cookie 窃取攻撃を無効化できる。

## セットアップ

### 1. 起動

```sh
docker compose up --build
```

### 2. Chrome の設定

`chrome://flags` で以下を **Enabled - For developers** に設定する:

- `Device Bound Session Credentials (Standard)`

> Chrome 145 時点では「Default」や「Enabled」では動作しなかった。「Enabled - For developers」に設定する必要がある。

### 3. アクセス

http://localhost:8080 を開き、`admin` / `password` でログインする。

## 動作確認

1. ログイン後、DevTools の Network タブで `POST /dbsc/start` が呼ばれることを確認
2. Cookie の Max-Age (600s) 経過前後に `POST /dbsc/refresh` が自動実行されることを確認
3. `chrome://device-bound-sessions/` でセッション状態を確認

## プロトコルフロー

### Registration (ログイン時)

```
Client                          Server
  |  POST /login                  |
  |  <----  Set-Cookie + Secure-Session-Registration header
  |                               |
  |  POST /dbsc/start             |
  |  Secure-Session-Response: <JWT with public key>
  |  <----  Session config JSON
```

1. サーバーがログイン成功時に短寿命 Cookie と `Secure-Session-Registration` ヘッダーを返す
2. Chrome が TPM 鍵ペアを生成し、公開鍵を含む ES256 署名付き JWT を `/dbsc/start` に送信
3. サーバーが JWT を検証して公開鍵を保存し、セッション設定 JSON を返す

### Refresh (Cookie 期限切れ前後に Chrome が自動実行)

```
Client                          Server
  |  POST /dbsc/refresh           |
  |  Sec-Secure-Session-Id: <id>  |
  |  <----  403 + Secure-Session-Challenge header
  |                               |
  |  POST /dbsc/refresh           |
  |  Secure-Session-Response: <signed JWT>
  |  <----  200 + Set-Cookie + Secure-Session-Challenge header
```

1. Chrome が `/dbsc/refresh` にセッション ID 付きでリクエスト
2. サーバーが `403` と `Secure-Session-Challenge` ヘッダーで challenge を発行
3. Chrome が challenge に署名して再リクエスト
4. サーバーが JWT を検証し、新しい Cookie と次回用の challenge を発行

## 仕様 (Working Draft) と Chrome 145 の実装差異

DBSC 仕様はまだ W3C Working Draft の段階であり、Chrome の実装との間にいくつかの差異がある。この実装では Chrome の実際の挙動に合わせつつ、仕様準拠にもフォールバックする方針をとっている。

| 項目 | 仕様 (§9.10) | Chrome 145 | この実装の対応 |
|------|-------------|------------|--------------|
| 登録 JWT の公開鍵の位置 | ペイロードの `key` クレーム | JWS ヘッダーの `jwk` パラメータ | `key` を優先、なければ `jwk` にフォールバック |
| リフレッシュ JWT の `sub` クレーム | MUST (セッション識別子) | 含まれない | 検証しない |

いずれもセキュリティ上の影響はない:

- **公開鍵の位置**: JWT の署名をその公開鍵で検証するため、どこに含まれていても改ざんされていれば署名検証が失敗する
- **`sub` の省略**: リフレッシュ時は `Sec-Secure-Session-Id` ヘッダーでセッションを特定し、そのセッションに紐づく公開鍵で署名を検証する。署名が通る = 正しいセッションの秘密鍵を持っているので、`sub` による二重確認は不要

## 実装上の注意点

- `credentials.attributes` の値は実際の `Set-Cookie` の属性と一致させる必要がある (仕様 §8.6)。不一致だと Chrome がセッションを無視する。この実装では `COOKIE_ATTRS` を一元定義し、`set_cookie()` と `credentials.attributes` の両方をそこから生成することで不一致を防いでいる
- 属性の一致判定に使われるのは `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite` の 5 つ。`Max-Age`/`Expires` はスコープ判定に関係しないため含めない
- リフレッシュのタイミングはブラウザが Cookie の `Max-Age` を見て自動的に決定する。サーバーから直接制御するパラメータはない

## ファイル構成

```
app/
├── server.py       # Flask ルーティング + DBSC プロトコル処理
├── dbsc.py         # JWT 検証 (ES256) + セッションストア
├── templates/
│   └── index.html
└── static/
    ├── app.js      # ログイン/ログアウト + ステータスポーリング
    └── style.css
```
