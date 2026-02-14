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
2. Cookie の Max-Age (600s) 経過後に `POST /dbsc/refresh` が自動実行されることを確認
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
  |  <----  Session config JSON + Set-Cookie
```

1. サーバーがログイン成功時に短寿命 Cookie と `Secure-Session-Registration` ヘッダーを返す
2. Chrome が TPM 鍵ペアを生成し、公開鍵を含む ES256 署名付き JWT を `/dbsc/start` に送信
3. サーバーが JWT を検証して公開鍵を保存し、セッション設定 JSON を返す

### Refresh (Cookie 期限切れ時に Chrome が自動実行)

```
Client                          Server
  |  POST /dbsc/refresh           |
  |  Sec-Secure-Session-Id: <id>  |
  |  <----  403 + Secure-Session-Challenge header
  |                               |
  |  POST /dbsc/refresh           |
  |  Secure-Session-Response: <signed JWT>
  |  <----  200 + Set-Cookie
```

1. Chrome が `/dbsc/refresh` にセッション ID 付きでリクエスト
2. サーバーが `403` と `Secure-Session-Challenge` ヘッダーで challenge を発行
3. Chrome が challenge に署名して再リクエスト
4. サーバーが JWT を検証し新しい Cookie を発行

## 実装上の注意点

- `/dbsc/start` のレスポンスに含める `credentials.attributes` の値は、実際の `Set-Cookie` の属性と完全に一致させる必要がある。不一致だと Chrome がセッションを無視する
- `credentials.attributes` に使える属性は `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite` の 5 つのみ。`Max-Age` 等を含めると Chrome がセッションを拒否する

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
