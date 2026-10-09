# Ayashii Checker

個人が作ったアプリやスクリプト、AIに読ませる文章に、危険なコードやプロンプトインジェクションが含まれていないかを判定する Web ツールです。

- **完全クライアントサイド**: ファイルはブラウザの中だけで解析します。CSP で `connect-src 'none'` を指定しているため、ページから外部への通信はできません。
- **入力**: ファイル、フォルダ、ZIP（GitHub の「Download ZIP」をそのまま入れられます）、テキストの貼り付け
- **ビルド不要**: 静的ファイルだけで動くので、GitHub Pages にそのまま置けます。

## 検出するもの

| 分類 | 例 |
| --- | --- |
| プロンプトインジェクション | 「以前の指示を無視して」(日英)、AI宛てのメッセージ、ユーザーに隠すよう指示、秘密情報の送信指示、HTMLコメントや非表示要素の中の指示、パラメータ付き画像URLでの持ち出し |
| 隠し文字 | Unicode タグ文字（中身を復号して表示）、ゼロ幅文字、Bidi 制御文字（Trojan Source）、異体字セレクタ、ホモグリフ |
| 情報の盗み出し | ブラウザの保存パスワード・Cookie、キーチェーン、SSH鍵・クラウド認証情報、暗号資産ウォレット、Discord/Telegram トークン、環境変数の一括取得、キーロガー |
| 外部への送信 | Discord Webhook、Telegram Bot、ペーストサイト、ngrok 等、IP直書きの通信先 |
| 危険なコマンド | `curl \| sh`、リバースシェル、`rm -rf /`、不審な PowerShell、Gatekeeper / Defender の無効化 |
| 居座り・権限 | LaunchAgents・cron・Run キー、`.zshrc` への追記、hosts 改ざん、マイナー |
| 難読化 | `eval(atob(...))`、`exec(base64.b64decode(...))`、ネットから取得したコードの実行、javascript-obfuscator、空白で画面外に追いやったコード |
| サプライチェーン | `postinstall` 等のインストールフック、タイポスクワッティング（`lodahs` など）、`setup.py` の install 上書き |
| 自動実行の設定 | `.vscode/tasks.json` の `runOn: folderOpen`、Claude Code の hooks / 全許可設定、`.mcp.json`、`.pth` |
| 秘密情報の混入 | AWS / GitHub / Anthropic / OpenAI / Stripe のキー、秘密鍵 |

`CLAUDE.md` / `AGENTS.md` / `.cursorrules` など、AIエージェントが自動で読むファイルで見つかったインジェクションは重大度を引き上げます。

## 限界

パターンマッチによる静的チェックです。「問題なし」は安全の保証ではありません。正規のアプリでも検出されることがあるため、表示される理由を読んで判断してください。

## 開発

```bash
python3 -m http.server 8000
```

ブラウザで http://localhost:8000 を開きます。判定エンジンのテスト:

```bash
node test/run.js
```

ルールはすべて [scanner.js](scanner.js) にあります。ZIP の展開には [JSZip](https://stuk.github.io/jszip/) (MIT) を `vendor/` に同梱しています。

## GitHub Pages で公開

リポジトリの Settings → Pages で、Source を「Deploy from a branch」、Branch を `main` / `/ (root)` にします。
