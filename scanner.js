/*
 * Ayashii Checker - scanning engine
 * すべてブラウザ内で動作する静的解析。ファイルの中身はどこにも送信しない。
 * Node.js からも require して使える（テスト用）。
 */
(function (root) {
  'use strict';

  const SEV = {
    critical: { label: '致命的', weight: 40, rank: 4 },
    high: { label: '高', weight: 20, rank: 3 },
    medium: { label: '中', weight: 8, rank: 2 },
    low: { label: '低', weight: 2, rank: 1 },
  };

  const CAT = {
    injection: 'プロンプトインジェクション',
    hidden: '隠し文字',
    code: '危険なコマンド',
    steal: '情報の盗み出し',
    exfil: '外部への送信',
    persist: '居座り・権限変更',
    obf: '難読化',
    supply: 'サプライチェーン',
    autorun: '自動実行の設定',
    secret: '秘密情報の混入',
  };

  const LINE_HIT_LIMIT = 10; // 1ファイル・1ルールあたりに記録する最大件数

  // ---------------------------------------------------------------------------
  // 行単位のルール
  // ---------------------------------------------------------------------------
  const R = (id, cat, sev, title, desc, re, opt = {}) => ({ id, cat, sev, title, desc, re, ...opt });

  const INJECTION_RULES = [
    R('inj-ignore-en', 'injection', 'high', '過去の指示を無視させる命令',
      'AIに元の指示を捨てさせる典型的なインジェクション文です。',
      /\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|every\s+)?(of\s+)?(the\s+|your\s+|my\s+)?(previous|prior|above|earlier|preceding|original|system|initial)\s+(instructions?|prompts?|messages?|rules|guidelines|directions|context)/i),
    R('inj-ignore-ja', 'injection', 'high', '過去の指示を無視させる命令',
      'AIに元の指示を捨てさせる典型的なインジェクション文です。',
      /(以前|前|これまで|今まで|上記|上|先程|先ほど|元|最初|システム)の(すべての|全ての|全)?(指示|命令|ルール|プロンプト|設定|制約|ガイドライン)(を|は)?(すべて|全て)?(無視|忘れ|破棄|リセット|上書き)/),
    R('inj-role-en', 'injection', 'medium', 'AIの役割を書き換える文',
      '「あなたは今から〜」のようにAIの人格・権限を差し替えようとしています。',
      /\b(you\s+are\s+now|from\s+now\s+on,?\s+you\s+(are|will|must)|act\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken)|pretend\s+(to\s+be|you\s+are)\s+(an?\s+)?(unrestricted|different|new)\s+(ai|assistant|model))/i),
    R('inj-role-ja', 'injection', 'medium', 'AIの役割を書き換える文',
      '「あなたは今から〜」のようにAIの人格・権限を差し替えようとしています。',
      /(あなた|君|お前)は(今から|これから|今後|以後)|(制限|制約|フィルター)の?(ない|無い|外れた)(AI|アシスタント|モード)/),
    R('inj-addressed-en', 'injection', 'high', 'AIに宛てたメッセージ',
      '文書の読者ではなく、文書を読み込んだAIに向けて書かれた指示です。',
      /\b((note|message|instructions?|attention|important)\s+(to|for)\s+(the\s+|any\s+|all\s+)?(ai|assistant|llm|agent|model|claude|chatgpt|gpt|copilot|gemini|bot)s?\b|\bif\s+you\s+are\s+(an?\s+)?(ai|llm|language\s+model|assistant|agent|claude|chatgpt)\b|\b(dear|hey|hi)\s+(ai|assistant|llm|claude|chatgpt|agent)\b)/i),
    R('inj-addressed-ja', 'injection', 'high', 'AIに宛てたメッセージ',
      '文書の読者ではなく、文書を読み込んだAIに向けて書かれた指示です。',
      /((AI|ＡＩ|エージェント|アシスタント|言語モデル|LLM|Claude|ChatGPT|Copilot|Gemini)(への|へ|向け|に対する)(の)?(指示|命令|メッセージ|お願い|注意))|(もし|仮に)?(あなた|これを読んでいるの)が(AI|ＡＩ|エージェント|アシスタント|言語モデル|LLM)(なら|であれば|の場合)/),
    R('inj-secret-en', 'injection', 'high', 'ユーザーに隠すよう指示',
      '「ユーザーには言うな」はインジェクションが発覚しないようにする常套句です。',
      /\b(do\s+not|don'?t|never|without)\s+(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|show(ing)?|notify(ing)?|alert(ing)?|let(ting)?)\s+.{0,30}\b(the\s+)?(user|human|operator|owner)\b/i),
    R('inj-secret-ja', 'injection', 'high', 'ユーザーに隠すよう指示',
      '「ユーザーには言うな」はインジェクションが発覚しないようにする常套句です。',
      /(ユーザー|ユーザ|利用者|人間|使用者|持ち主)(に|へ|には|へは)(この|これを|これは|このこと)?.{0,10}(伝え|言わ|言う|知らせ|見せ|報告|表示|通知|教え)(ない|るな|ずに|てはいけない|ないで)/),
    R('inj-exfil-en', 'injection', 'high', '秘密情報の送信を求める指示',
      'APIキーやパスワードなどを外部へ送らせようとしています。',
      /\b(send|post|upload|forward|email|transmit|paste|exfiltrate|leak|include)\b.{0,50}\b(api[\s_-]?keys?|passwords?|tokens?|credentials?|secrets?|private\s+keys?|\.env|ssh\s+keys?|cookies?|session)/i),
    R('inj-exfil-ja', 'injection', 'high', '秘密情報の送信を求める指示',
      'APIキーやパスワードなどを外部へ送らせようとしています。',
      /(APIキー|ＡＰＩキー|パスワード|トークン|認証情報|秘密鍵|シークレット|\.env|環境変数|クッキー|Cookie).{0,25}(送信|送って|送れ|送る|アップロード|転送|貼り付け|POST|書き込|含め)/),
    R('inj-exec-en', 'injection', 'medium', 'コマンド実行を促す指示',
      'AIエージェントにコマンドを実行させようとする文です。',
      /\b(run|execute|eval|invoke)\s+(the\s+)?(following|this|below)\s+(shell\s+|bash\s+|terminal\s+)?(command|code|script)s?\b(?!.{0,20}\b(to\s+install|in\s+your\s+terminal)\b)/i),
    R('inj-exec-ja', 'injection', 'medium', 'コマンド実行を促す指示',
      'AIエージェントにコマンドを実行させようとする文です。',
      /(次の|以下の|下記の|この)(コマンド|コード|スクリプト|シェル)を(すぐに|今すぐ|黙って|確認せずに|自動で)?(実行|走らせ)/),
    R('inj-token', 'injection', 'medium', 'チャット形式の制御トークン',
      'モデル内部の区切り記号を偽装し、システム指示に見せかける手口です。',
      /<\|(im_start|im_end|endoftext|system|start_header_id|end_header_id|eot_id)\|>|\[\/?INST\]|<<\/?SYS>>|<\/?(system|system_prompt|admin_instructions)>|^\s*#{0,3}\s*(SYSTEM|System)\s*(:|：)\s*\S/m),
    R('inj-jailbreak', 'injection', 'medium', '脱獄（ジェイルブレイク）の語句',
      'AIの安全制限を外そうとする既知のフレーズです。',
      /\b(DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+(enabled|on)|jailbreak(ed)?\s+mode|god\s+mode\s+enabled)\b|ジェイルブレイク|脱獄モード|開発者モード(を|に)(有効|オン)/i),
    R('inj-sysprompt', 'injection', 'low', 'システムプロンプトへの言及',
      '単独では問題ないことも多いですが、他の検出と組み合わさると要注意です。',
      /\b(system\s+prompt|initial\s+instructions|hidden\s+instructions)\b|システムプロンプト|隠し(指示|命令)/i),
    R('inj-img-exfil', 'injection', 'medium', 'パラメータ付きの画像URL',
      'Markdown画像のURLにデータを載せて送る「画像経由の持ち出し」に使われる形です。',
      /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?&][\w.-]*=[^)\s]*(\{|\$|%7B|<)[^)]*\)|!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?&](q|data|d|c|secret|key|token|info|msg|content)=[^)]*\)/i),
  ];

  const CODE_RULES = [
    // --- 危険なコマンド
    R('cmd-pipe-shell', 'code', 'high', 'ダウンロードしたものを即シェルで実行',
      'ネット上のスクリプトを中身を確認せず実行します（curl | sh）。配布元が信頼できるか要確認。',
      /\b(curl|wget|iwr|Invoke-WebRequest)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b/i),
    R('cmd-download-run', 'code', 'high', 'ファイルをダウンロードして実行',
      'ダウンロードしたファイルに実行権限を付けて起動しています。',
      /\b(curl|wget)\b[^\n]*(-o|-O|--output|>)\s*\S+[^\n]*(&&|;)\s*(chmod\s+\+x|\.\/|(ba)?sh\s|open\s)/),
    R('cmd-rm-root', 'code', 'critical', 'システム全体の削除',
      'ルートやホームディレクトリを丸ごと削除するコマンドです。',
      /\brm\s+(-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(--no-preserve-root\s+)?(\/|\/\*|~\/?|\$HOME\/?|"\$HOME"\/?)(\s|$|;|&|\))/),
    R('cmd-disk-wipe', 'code', 'critical', 'ディスクの破壊・初期化',
      'ディスクを直接上書き・フォーマットします。',
      /\bmkfs(\.\w+)?\s+\/dev\/|\bdd\s+[^\n]*of=\/dev\/(sd|disk|nvme|hd|rdisk)|diskutil\s+(eraseDisk|zeroDisk|secureErase)|\bformat\s+[a-z]:\s*\/[qy]/i),
    R('cmd-forkbomb', 'code', 'critical', 'フォーク爆弾',
      'プロセスを無限に増やしてPCを停止させます。',
      /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/),
    R('cmd-revshell', 'code', 'critical', 'リバースシェル',
      '外部の攻撃者にこのPCの操作権を渡す典型的なコードです。',
      /\/dev\/tcp\/[\w.-]+\/\d+|\bnc(at)?\b[^\n]*\s-[a-z]*e\s+\/bin\/(ba|z)?sh|\bbash\s+-i\s*>&|\bos\.dup2\s*\(\s*\w+\.fileno\(\)|\bpty\.spawn\s*\(\s*["']\/bin\/(ba)?sh|New-Object\s+System\.Net\.Sockets\.TCPClient/i),
    R('cmd-powershell', 'code', 'high', '不審なPowerShell実行',
      'エンコード済みコマンド・非表示ウィンドウ・ダウンロード即実行など、マルウェアで多用される形です。',
      /powershell(\.exe)?\b[^\n]*\s-(enc|encodedcommand|e|ec)\s+[A-Za-z0-9+\/=]{16,}|powershell(\.exe)?\b[^\n]*-w(indowstyle)?\s+hidden|\b(IEX|Invoke-Expression)\b\s*[(\s]|\.DownloadString\s*\(|\.DownloadFile\s*\(|-ExecutionPolicy\s+Bypass/i),
    R('cmd-gatekeeper', 'code', 'high', 'macOSの安全機能を無効化',
      'Gatekeeper（未確認アプリの警告）やSIPを外そうとしています。',
      /xattr\s+(-[a-z]*\s+)*-[a-z]*[dc][a-z]*\s+(com\.apple\.quarantine)?|spctl\s+--master-disable|spctl\s+--global-disable|csrutil\s+disable/),
    R('cmd-defender', 'code', 'high', 'Windowsのセキュリティを無効化',
      'Windows Defenderや除外設定を変更しています。',
      /Set-MpPreference\s+[^\n]*-(DisableRealtimeMonitoring|ExclusionPath|ExclusionProcess)|Add-MpPreference\s+-Exclusion/i),
    R('cmd-child-process', 'code', 'low', '外部コマンドの実行機能',
      'OSコマンドを呼び出せる機能を使っています。何を実行しているか確認してください。',
      /require\(\s*['"](node:)?child_process['"]\s*\)|from\s+['"](node:)?child_process['"]|\bos\.(system|popen|exec[lv]p?e?)\s*\(|Runtime\.getRuntime\(\)\.exec\(|\bshell_exec\s*\(|\bproc_open\s*\(|Process\.Start\s*\(/),
    R('cmd-shell-true', 'code', 'medium', 'shell=True でのコマンド実行',
      '文字列をそのままシェルに渡すため、組み立て次第で危険になります。',
      /subprocess\.\w+\([^\n]*shell\s*=\s*True/),
    R('cmd-sudo', 'persist', 'low', '管理者権限（sudo）の使用',
      '管理者権限で何かを実行します。必要性を確認してください。',
      /(^|[\s;&|`(])sudo\s+(?!-v\b)/),
    R('cmd-chmod', 'persist', 'medium', '危険な権限変更',
      'setuid付与や誰でも書き込める権限（777）への変更です。',
      /\bchmod\s+(-R\s+)?([ugoa]*\+s|[2467][0-7]{3}\b|777\b|a\+rwx)/),

    // --- 情報の盗み出し
    R('steal-browser', 'steal', 'critical', 'ブラウザの保存パスワード・Cookieへのアクセス',
      'ブラウザが保存したログイン情報やCookieのファイルを読んでいます。情報窃取型マルウェアの特徴です。',
      /['"\/\\](Login Data|Cookies|Web Data|Local State)['"\\\/]|Application Support\/(Google\/Chrome|BraveSoftware|Microsoft Edge|Firefox|Arc)|AppData\\+(Local|Roaming)\\+(Google|Mozilla|BraveSoftware|Microsoft\\+Edge|Opera)|\b(key4\.db|logins\.json|cookies\.sqlite|signons\.sqlite)\b|browser_cookie3|CryptUnprotectData/),
    R('steal-keychain', 'steal', 'critical', 'キーチェーン（パスワード保管庫）の読み出し',
      'macOSのキーチェーンからパスワードを取り出そうとしています。',
      /\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain|export)\b|login\.keychain(-db)?\b|Keychains\/[^'"\s]*\.keychain/),
    R('steal-ssh-cloud', 'steal', 'high', 'SSH鍵・クラウド認証情報へのアクセス',
      'SSH秘密鍵やAWS/GCP/GitHub等の認証ファイルを参照しています。',
      /\.ssh\/(id_[a-z0-9]+|identity)\b|\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.aws\/credentials|\.config\/gcloud|application_default_credentials\.json|\.kube\/config|\.docker\/config\.json|\.git-credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.config\/gh\/hosts\.yml/),
    R('steal-wallet', 'steal', 'high', '暗号資産ウォレットへのアクセス',
      '仮想通貨ウォレットのデータを探しています。',
      /\bwallet\.dat\b|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|Exodus[\\\/]exodus\.wallet|Electrum[\\\/]wallets|\.solana\/id\.json|keystore[\\\/]UTC--|Ethereum[\\\/]keystore|atomic[\\\/]Local Storage/i),
    R('steal-messenger', 'steal', 'critical', 'チャットアプリのトークンへのアクセス',
      'Discord/Telegram/Slack等のログイン情報が入ったフォルダを読んでいます。',
      /discord(canary|ptb)?[\\\/]Local Storage|Local Storage[\\\/]leveldb|Telegram Desktop[\\\/]tdata|\btdata[\\\/]|Slack[\\\/](Cookies|storage)/i),
    R('steal-env-dump', 'steal', 'high', '環境変数をまとめて取得',
      '環境変数（APIキー等が入りがち）を丸ごと集めています。',
      /JSON\.stringify\(\s*process\.env\s*\)|Object\.(keys|entries|values)\(\s*process\.env\s*\)|\.\.\.process\.env\b(?!\s*[,}]\s*\w+\s*:)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|json\.dumps\(\s*(dict\()?os\.environ|Get-ChildItem\s+env:|\bprintenv\s*\|/),
    R('steal-keylogger', 'steal', 'high', 'キー入力の監視（キーロガー）',
      'キーボード入力をこっそり記録する機能です。',
      /pynput\.keyboard|keyboard\.on_press|keyboard\.hook\(|GetAsyncKeyState|SetWindowsHookEx|CGEventTapCreate|NSEvent\.addGlobalMonitorForEvents/),
    R('steal-screen', 'steal', 'medium', '画面・クリップボードの取得',
      '画面キャプチャやクリップボードの読み取りをしています。用途を確認してください。',
      /ImageGrab\.grab|pyautogui\.screenshot|\bscreencapture\s+-|\bmss\(\)\.grab|pyperclip\.paste\(|\bpbpaste\b|navigator\.clipboard\.readText/),
    R('steal-browser-js', 'steal', 'low', 'Cookie・ローカル保存データの読み取り',
      'Webページ内で cookie やトークンを読み取っています。送信先を確認してください。',
      /document\.cookie(?!\s*=)|localStorage\.getItem\(\s*['"][^'"]*(token|auth|jwt|session|key)/i),

    // --- 外部への送信
    R('exfil-webhook', 'exfil', 'high', 'Discord/Telegram への送信',
      'Discord Webhook や Telegram Bot は盗んだ情報の送り先として非常によく使われます。',
      /discord(app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot/i),
    R('exfil-paste', 'exfil', 'high', '使い捨て・匿名アップロード先',
      'ペーストサイトやリクエスト受信サービスは、データの持ち出し先として悪用されがちです。',
      /\b(pastebin\.com|paste\.ee|hastebin\.com|ghostbin|transfer\.sh|anonfiles\.com|file\.io|0x0\.st|gofile\.io|webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator\.net|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|localtunnel\.me|canarytokens)\b/i),
    R('exfil-raw-ip', 'exfil', 'medium', 'IPアドレス直書きの通信先',
      'ドメイン名を使わずIPアドレスへ直接通信しています。',
      /\b(https?|wss?|tcp|ftp):\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?/i,
      { filter: (m) => !/:\/\/(127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|255\.)/.test(m[0]) }),
    R('exfil-beacon', 'exfil', 'medium', 'Cookie等を外部へ送信',
      '読み取ったCookieやストレージの内容をネットワークへ送っています。',
      /(fetch|sendBeacon|XMLHttpRequest|axios\.\w+|\$\.(get|post|ajax)|new\s+Image\(\)\.src\s*=)[^\n]{0,150}(document\.cookie|localStorage|sessionStorage)/),

    // --- 居座り
    R('persist-launch', 'persist', 'medium', '自動起動の登録',
      'ログイン時や定期的に自動で動くように登録しています。',
      /LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap|submit)|\bcrontab\s+(-[a-z]\s+)*[^\s-]|\/etc\/cron|CurrentVersion\\+Run(Once)?\b|schtasks(\.exe)?\s+\/create|systemctl\s+(--user\s+)?enable|Startup\\+[^"'\s]*\.(lnk|bat|vbs|exe)|osascript[^\n]*login item/i),
    R('persist-shellrc', 'persist', 'high', 'シェル設定ファイルへの追記',
      '.bashrc / .zshrc 等に書き込み、ターミナルを開くたびに実行させようとしています。',
      /(>>|appendFile(Sync)?\s*\(|open\([^)\n]*,\s*['"]a['"])[^\n]{0,80}\.(bashrc|zshrc|bash_profile|zprofile|profile)\b|\.(bashrc|zshrc|bash_profile|zprofile)['"]?\s*,\s*['"]a['"]/),
    R('persist-hosts', 'persist', 'high', 'hostsファイルの書き換え',
      '名前解決を書き換え、偽サイトに誘導できます。',
      /(>>|>|writeFile|appendFile|open\()[^\n]{0,40}(\/etc\/hosts|drivers\\+etc\\+hosts)/),
    R('persist-miner', 'persist', 'high', '暗号資産マイニング',
      'PCの計算資源を勝手に使って仮想通貨を採掘する仕組みです。',
      /stratum\+(tcp|ssl):\/\/|\bxmrig\b|coinhive|cryptonight|minexmr|nicehash|\bmoneroocean\b/i),

    // --- 難読化
    R('obf-eval-decode', 'obf', 'critical', '暗号化・圧縮したコードをその場で実行',
      '中身を隠したコードを復元して即実行しています。正規アプリではまず見かけない形です。',
      /\beval\s*\(\s*(atob|unescape|decodeURIComponent|Buffer\.from|String\.fromCharCode|require\(['"]zlib)|\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)|new\s+Function\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent)|\bexec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode|lzma\.decompress|bz2\.decompress|__import__\(\s*['"](base64|zlib|marshal))|\bexec\s*\(\s*(requests\.get|urllib\.request\.urlopen|urlopen)\s*\(|\beval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/),
    R('obf-remote-exec', 'obf', 'critical', 'ネットから取得したコードを実行',
      'サーバーから取ってきた文字列をそのままプログラムとして実行します。後から中身を差し替えられます。',
      /(eval|new\s+Function|exec)\s*\([^\n]{0,40}(await\s+)?(fetch|axios|https?\.get|requests\.get|urlopen)\s*\(|\.then\(\s*\w+\s*=>\s*\w+\.text\(\)\s*\)\s*\.then\(\s*eval\s*\)/),
    R('obf-base64-blob', 'obf', 'medium', '長大なBase64文字列',
      'データやコードを隠すために使われることがあります。画像・フォントの埋め込みなら問題ありません。',
      /['"`][A-Za-z0-9+\/]{300,}={0,2}['"`]/,
      { filter: (m, line) => !/data:(image|font|audio|video)\/|\.(png|jpe?g|gif|woff2?|svg)|font-face/i.test(line) }),
    R('obf-hex-escape', 'obf', 'medium', '大量の16進エスケープ',
      '文字列を読めない形に変換してあります。',
      /(\\x[0-9a-fA-F]{2}){40,}|(\\u[0-9a-fA-F]{4}){30,}/),
    R('obf-charcode', 'obf', 'medium', '文字コード配列からの文字列組み立て',
      'String.fromCharCode / chr() で文字列を組み立てて中身を隠す手口です。',
      /fromCharCode\(\s*(\d+\s*,\s*){20,}|(chr\(\d+\)\s*\+\s*){15,}/),
    R('obf-dynamic-exec', 'obf', 'low', '動的なコード実行（eval/exec）',
      '文字列をプログラムとして実行します。引数の出どころを確認してください。',
      /(^|[^\w.$])(eval|exec)\s*\((?!\s*\))/,
      { filter: (m, line) => !/\.exec\(|regex|RegExp|re\.compile|cursor\.exec|db\.exec|\bexecute\(/.test(line) }),
    R('supply-install-hook-py', 'supply', 'medium', 'インストール時に任意コードを実行（Python）',
      'pip install した瞬間に setup.py 内のコードが動きます。',
      /cmdclass\s*=\s*\{[^}\n]*['"](install|develop|egg_info)['"]/),

    // --- 秘密情報の混入
    R('secret-key', 'secret', 'medium', 'APIキー・秘密鍵の直書き',
      'コード内に認証情報が書かれています。作者のミスか、盗んだ鍵の流用の可能性があります。',
      /\bAKIA[0-9A-Z]{16}\b|\bsk-(ant-(api|admin)\d{2}-)?[A-Za-z0-9_-]{32,}|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}|\bxox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----|\bAIza[0-9A-Za-z_-]{35}\b|\b(sk|rk)_live_[0-9a-zA-Z]{24,}/),
  ];

  const LINE_RULES = INJECTION_RULES.concat(CODE_RULES);

  // ---------------------------------------------------------------------------
  // 隠し文字
  // ---------------------------------------------------------------------------
  const ZERO_WIDTH = new Set([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2061, 0x2062, 0x2063, 0x2064]);
  const BIDI = new Set([0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F]);
  const isTag = (cp) => cp >= 0xE0000 && cp <= 0xE007F;
  const isVariationSelectorSup = (cp) => cp >= 0xE0100 && cp <= 0xE01EF;

  function isInvisible(cp) {
    return ZERO_WIDTH.has(cp) || BIDI.has(cp) || isTag(cp) || isVariationSelectorSup(cp);
  }

  function scanHiddenChars(path, lines, out) {
    let zwTotal = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!/[­͏؜ᅟᅠ᠎​-‏‪-‮⁠-⁩ㅤ﻿ﾠ\uDB40]/.test(line)) continue;
      let tags = '', tagCount = 0, bidi = 0, zw = 0, vs = 0, col = -1, idx = 0;
      for (const ch of line) {
        const cp = ch.codePointAt(0);
        if (isTag(cp)) {
          tagCount++;
          if (cp >= 0xE0020 && cp <= 0xE007E) tags += String.fromCharCode(cp - 0xE0000);
          if (col < 0) col = idx;
        } else if (BIDI.has(cp)) {
          if (!(cp === 0x200E || cp === 0x200F)) bidi++;
          if (col < 0 && cp !== 0x200E && cp !== 0x200F) col = idx;
        } else if (ZERO_WIDTH.has(cp)) {
          if (!(cp === 0xFEFF && i === 0 && idx === 0)) {
            zw++;
            if (col < 0) col = idx;
          }
        } else if (isVariationSelectorSup(cp)) {
          vs++;
          if (col < 0) col = idx;
        }
        idx += ch.length;
      }
      if (tagCount) {
        out.push(finding(path, i, line, col, 'hidden-tag', 'hidden', 'critical', '不可視の「タグ文字」に隠されたテキスト',
          '画面には一切表示されないが、AIにはそのまま読める文字列です（ASCIIスマグリング）。AIへの隠し命令に使われます。',
          { decoded: tags }));
      }
      if (vs >= 8) {
        out.push(finding(path, i, line, col, 'hidden-vs', 'hidden', 'high', '異体字セレクタを使った隠しデータ',
          `表示されない異体字セレクタが${vs}個並んでいます。データを埋め込む手口に使われます。`,
          { decoded: decodeVariationSelectors(line) }));
      }
      if (bidi) {
        out.push(finding(path, i, line, col, 'hidden-bidi', 'hidden', 'high', '文字の表示順を入れ替える制御文字',
          '見た目と実際の中身を食い違わせる「Trojan Source」攻撃に使われます。コードの見た目を信用しないでください。', {}));
      }
      if (zw) {
        zwTotal += zw;
        const many = zw >= 8;
        out.push(finding(path, i, line, col, 'hidden-zw', 'hidden', many ? 'high' : 'medium',
          many ? '大量のゼロ幅文字（隠しデータの疑い）' : 'ゼロ幅・不可視文字',
          many ? `見えない文字が${zw}個あります。情報を埋め込んだり、検出を逃れたりする目的が考えられます。`
               : `見えない文字が${zw}個あります。コピペ由来のこともありますが、単語を分断して検出を逃れる手口にも使われます。`,
          { decoded: many ? decodeZeroWidthBinary(line) : undefined }));
      }
      if (out.length > 2000) break;
    }
    return zwTotal;
  }

  // ゼロ幅文字 2種を 0/1 とみなして復号を試みる（よくあるステガノ形式）
  function decodeZeroWidthBinary(line) {
    const bits = [];
    for (const ch of line) {
      if (ch === '​') bits.push('0');
      else if (ch === '‌') bits.push('1');
    }
    if (bits.length < 16) return undefined;
    let s = '';
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      const c = parseInt(bits.slice(i, i + 8).join(''), 2);
      if (c < 9 || c > 126) return undefined;
      s += String.fromCharCode(c);
    }
    return s || undefined;
  }

  function decodeVariationSelectors(line) {
    const bytes = [];
    for (const ch of line) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xFE00 && cp <= 0xFE0F) bytes.push(cp - 0xFE00);
      else if (isVariationSelectorSup(cp)) bytes.push(cp - 0xE0100 + 16);
    }
    try {
      const s = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
      return /^[\x09\x0A\x0D\x20-\x7E　-鿿＀-￯]+$/.test(s) ? s : undefined;
    } catch (e) {
      return undefined;
    }
  }

  // ---------------------------------------------------------------------------
  // ファイル単位のチェック
  // ---------------------------------------------------------------------------
  const POPULAR_NPM = ['react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'moment', 'request', 'vue', 'next', 'webpack', 'typescript', 'eslint', 'jquery', 'dotenv', 'cross-env', 'uuid', 'debug', 'colors', 'discord.js', 'electron', 'mongoose', 'socket.io', 'body-parser', 'cors', 'nodemon', 'prettier', 'babel-cli', 'bcrypt', 'jsonwebtoken', 'node-fetch', 'puppeteer', 'playwright', 'vite', 'tailwindcss', 'openai', 'yargs', 'inquirer', 'mysql', 'mysql2', 'sqlite3', 'redis', 'ethers', 'web3', 'solana', 'coffee-script', 'nodemailer', 'sharp', 'zod', 'prisma', 'svelte', 'angular', 'rxjs', 'underscore', 'async', 'fs-extra', 'glob', 'minimist', 'semver', 'ws', 'got', 'esbuild', 'rollup', 'jest', 'mocha', 'ts-node', 'tslib', 'classnames', 'styled-components', 'react-router', 'redux', 'graphql', 'pg', 'mongodb', 'firebase', 'stripe', 'twilio', 'aws-sdk'];
  const POPULAR_PYPI = ['requests', 'numpy', 'pandas', 'flask', 'django', 'urllib3', 'setuptools', 'beautifulsoup4', 'selenium', 'matplotlib', 'scipy', 'pillow', 'cryptography', 'boto3', 'colorama', 'python-dateutil', 'pyyaml', 'openai', 'anthropic', 'tensorflow', 'torch', 'fastapi', 'uvicorn', 'pydantic', 'httpx', 'aiohttp', 'scikit-learn', 'opencv-python', 'pytest', 'jinja2', 'click', 'rich', 'tqdm', 'pymongo', 'psycopg2', 'sqlalchemy', 'discord.py', 'python-telegram-bot', 'pycryptodome', 'paramiko', 'web3', 'pygame', 'pyinstaller', 'langchain', 'transformers', 'streamlit', 'gradio', 'keras', 'seaborn', 'plotly', 'lxml', 'certifi', 'idna', 'six', 'wheel', 'pip', 'virtualenv', 'tweepy', 'pyautogui', 'pynput', 'termcolor', 'python-dotenv'];

  // 編集距離（隣り合う文字の入れ替えも1とカウント）
  function editDistance(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 99;
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 0; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
    return d[a.length][b.length];
  }

  function looksLikeTyposquat(name, popular) {
    const n = name.toLowerCase().replace(/^@[^/]+\//, '');
    if (popular.includes(n) || n.length < 4) return null;
    const norm = (s) => s.replace(/[-_.]/g, '');
    for (const p of popular) {
      if (norm(n) === norm(p)) return p;
      if (p.length >= 5 && editDistance(n, p) === 1) return p;
    }
    return null;
  }

  function lineOf(text, index) {
    let n = 0;
    for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
    return n;
  }

  function findLine(lines, needle) {
    for (let i = 0; i < lines.length; i++) if (lines[i].includes(needle)) return i;
    return 0;
  }

  function scanPackageJson(path, text, lines, out) {
    let pkg;
    try { pkg = JSON.parse(text); } catch (e) { return; }
    if (!pkg || typeof pkg !== 'object') return;
    const scripts = pkg.scripts || {};
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'preuninstall', 'postuninstall']) {
      const cmd = scripts[hook];
      if (typeof cmd !== 'string') continue;
      const benign = /^\s*(husky( install)?|node-gyp rebuild|tsc|npm run build|patch-package|ngcc|prebuild-install|is-ci \|\| husky|lefthook install|electron-builder install-app-deps)\b/.test(cmd);
      if (hook === 'prepare' && benign) continue;
      const i = findLine(lines, `"${hook}"`);
      out.push(finding(path, i, lines[i] || '', -1, 'supply-npm-hook', 'supply', benign ? 'low' : 'medium',
        `npm install 時に自動実行されるスクリプト（${hook}）`,
        'パッケージを入れただけで実行されます。マルウェアの侵入口として最も多い場所です。中身を確認してください。', {}));
    }
    const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies);
    for (const [name, ver] of Object.entries(deps)) {
      const like = looksLikeTyposquat(name, POPULAR_NPM);
      const i = findLine(lines, `"${name}"`);
      if (like) {
        out.push(finding(path, i, lines[i] || '', -1, 'supply-typosquat', 'supply', 'high',
          `有名パッケージに似た名前「${name}」（本物は「${like}」？）`,
          '一文字違いの偽パッケージ（タイポスクワッティング）の可能性があります。', {}));
      }
      if (typeof ver === 'string' && /^(https?:|git(\+\w+)?:|github:|[\w-]+\/[\w.-]+(#.*)?$|file:|\.{0,2}\/)/.test(ver) && !/^(npm:|workspace:)/.test(ver)) {
        out.push(finding(path, i, lines[i] || '', -1, 'supply-url-dep', 'supply', 'low',
          `npm公式以外から取得する依存「${name}」`,
          'GitHubやURL直指定の依存は中身の検証がされにくいです。', {}));
      }
    }
  }

  function scanRequirements(path, text, lines, out) {
    lines.forEach((line, i) => {
      const m = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/);
      if (!m || line.trim().startsWith('#') || line.trim().startsWith('-')) return;
      const like = looksLikeTyposquat(m[1], POPULAR_PYPI);
      if (like) {
        out.push(finding(path, i, line, 0, 'supply-typosquat', 'supply', 'high',
          `有名パッケージに似た名前「${m[1]}」（本物は「${like}」？）`,
          '一文字違いの偽パッケージ（タイポスクワッティング）の可能性があります。', {}));
      }
      if (/--(extra-)?index-url\s+https?:\/\/(?!pypi\.org|files\.pythonhosted\.org)/.test(line) || /^\s*-i\s+https?:/.test(line)) {
        out.push(finding(path, i, line, 0, 'supply-index', 'supply', 'medium', '非公式のパッケージ配布元',
          'PyPI以外からパッケージを取得します。', {}));
      }
    });
  }

  function scanAutorunConfigs(path, text, lines, out) {
    const p = path.replace(/\\/g, '/');
    if (/(^|\/)\.vscode\/tasks\.json$/.test(p) && /"runOn"\s*:\s*"folderOpen"/.test(text)) {
      const i = findLine(lines, 'folderOpen');
      out.push(finding(path, i, lines[i], -1, 'autorun-vscode', 'autorun', 'high', 'フォルダを開くだけで実行されるVS Codeタスク',
        'VS Codeでこのフォルダを開いた瞬間にコマンドが走ります。偽のプロジェクトを使った攻撃で実際に使われています。', {}));
    }
    if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(p)) {
      if (/"hooks"\s*:/.test(text)) {
        const i = findLine(lines, '"hooks"');
        out.push(finding(path, i, lines[i], -1, 'autorun-claude-hooks', 'autorun', 'medium', 'Claude Code のフック設定',
          'Claude Code の操作に合わせて自動でコマンドが実行されます。中身を確認してください。', {}));
      }
      if (/"enableAllProjectMcpServers"\s*:\s*true/.test(text)) {
        const i = findLine(lines, 'enableAllProjectMcpServers');
        out.push(finding(path, i, lines[i], -1, 'autorun-mcp-all', 'autorun', 'medium', 'MCPサーバーを確認なしで全許可',
          'プロジェクトに含まれるMCPサーバーを確認なしで起動する設定です。', {}));
      }
      if (/"Bash\(\*\)"|"Bash"\s*[,\]]|"defaultMode"\s*:\s*"bypassPermissions"/.test(text)) {
        const i = findLine(lines, 'Bash');
        out.push(finding(path, i, lines[i] || '', -1, 'autorun-claude-perm', 'autorun', 'high', 'AIエージェントに全コマンドを無確認で許可',
          'このフォルダで Claude Code を使うと、あらゆるコマンドが確認なしで実行される設定です。', {}));
      }
    }
    if (/(^|\/)\.mcp\.json$/.test(p) || /(^|\/)\.cursor\/mcp\.json$/.test(p)) {
      out.push(finding(path, 0, lines[0] || '', -1, 'autorun-mcp', 'autorun', 'low', 'MCPサーバーの定義ファイル',
        'AIツールが起動する外部プログラムが書かれています。command の中身を確認してください。', {}));
    }
    if (/\.pth$/.test(p) && /^\s*import\s/m.test(text)) {
      out.push(finding(path, 0, lines[0] || '', -1, 'autorun-pth', 'autorun', 'high', 'Python起動時に自動実行される .pth ファイル',
        'Pythonを起動するたびにこのコードが実行されます。', {}));
    }
    if (/(^|\/)(\.git\/hooks\/[^/.]+|\.husky\/[^/_]+)$/.test(p)) {
      out.push(finding(path, 0, lines[0] || '', -1, 'autorun-githook', 'autorun', 'low', 'Gitフック',
        'git操作のたびに自動で実行されるスクリプトです。', {}));
    }
    if (/\.(desktop|command|scpt|applescript|lnk|scr|vbs|vbe|wsf|hta|jse)$/i.test(p)) {
      out.push(finding(path, 0, lines[0] || '', -1, 'autorun-launcher', 'autorun', 'medium', 'ダブルクリックで実行されるファイル形式',
        `.${p.split('.').pop()} はダブルクリックでスクリプトが動く形式です。`, {}));
    }
  }

  function scanHiddenMarkup(path, text, lines, out) {
    // HTMLコメント / 非表示要素 の中にAI向けの指示がないか
    const zones = [];
    const commentRe = /<!--([\s\S]*?)-->/g;
    let m;
    while ((m = commentRe.exec(text)) && zones.length < 500) zones.push({ kind: 'HTMLコメント', start: m.index, body: m[1] });
    const hiddenRe = /<(\w+)[^>]*style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em|rem)?\s*[;"']|opacity\s*:\s*0(\.0+)?\s*[;"']|color\s*:\s*(#fff\b|#ffffff\b|white\b|transparent\b)|left\s*:\s*-\d{4,}px|height\s*:\s*0(px)?\s*;[^"']*overflow\s*:\s*hidden)[^"']*["'][^>]*>([\s\S]{0,2000}?)<\/\1>/gi;
    while ((m = hiddenRe.exec(text)) && zones.length < 1000) zones.push({ kind: '画面に表示されない要素', start: m.index, body: m[7] || '' });
    const ariaRe = /<(\w+)[^>]*(\shidden(\s|>|=)|aria-hidden\s*=\s*["']true["']|class\s*=\s*["'][^"']*\b(sr-only|visually-hidden|hidden)\b)[^>]*>([^<]{20,2000})<\/\1>/gi;
    while ((m = ariaRe.exec(text)) && zones.length < 1500) zones.push({ kind: '画面に表示されない要素', start: m.index, body: m[5] || '' });

    for (const z of zones) {
      const hits = INJECTION_RULES.filter((r) => r.sev !== 'low' && r.re.test(z.body));
      if (!hits.length) continue;
      const i = lineOf(text, z.start);
      out.push(finding(path, i, lines[i] || '', -1, 'inj-hidden-zone', 'injection', 'critical',
        `${z.kind}の中に隠されたAI向けの指示`,
        `人間には見えない場所に「${hits[0].title}」が書かれています。AIだけに読ませる意図が明確です。`,
        { decoded: z.body.trim().slice(0, 400) }));
    }
  }

  function scanObfuscationStats(path, text, lines, out) {
    const ids = text.match(/\b_0x[0-9a-f]{4,6}\b/g);
    if (ids && ids.length >= 20) {
      const i = findLine(lines, ids[0]);
      out.push(finding(path, i, lines[i], -1, 'obf-jsobf', 'obf', 'high', '難読化ツールで変換されたJavaScript',
        `「_0x…」形式の変数名が${ids.length}個あります。中身を読ませないための加工で、マルウェアでよく使われます。`, {}));
    }
    if (!/\.min\.(js|css)$|\.map$|(^|\/)dist\/|(^|\/)build\/|bundle|vendor|\.lock$|lock\.json$|\.svg$/i.test(path)) {
      const longIdx = lines.findIndex((l) => l.length > 5000);
      if (longIdx >= 0 && /\.(js|mjs|cjs|ts|py|sh|ps1|php|rb)$/i.test(path)) {
        out.push(finding(path, longIdx, lines[longIdx], -1, 'obf-longline', 'obf', 'low', '極端に長い1行',
          `${lines[longIdx].length.toLocaleString()}文字の行があります。圧縮済みか、中身を隠している可能性があります。`, {}));
      }
    }
    // 画面外に追い出した長い空白（横スクロールしないと見えないコード）
    const padIdx = lines.findIndex((l) => /\S[ \t]{150,}\S/.test(l));
    if (padIdx >= 0 && /\.(js|mjs|cjs|ts|py|sh|php|rb|json)$/i.test(path)) {
      out.push(finding(path, padIdx, lines[padIdx], -1, 'obf-whitespace', 'obf', 'high', '大量の空白の後ろに隠したコード',
        'エディタの右端の外に追いやって、コードを見えにくくする手口です。', {}));
    }
  }

  function scanHomoglyph(path, lines, out) {
    if (!/\.(js|mjs|cjs|ts|tsx|jsx|py|sh|json|php|rb|go|rs|java|cs|html?)$/i.test(path)) return;
    let n = 0;
    for (let i = 0; i < lines.length && n < 5; i++) {
      const m = lines[i].match(/[A-Za-z_][A-Za-z_]*[Ѐ-ӿͰ-Ͽ][A-Za-z_Ѐ-ӿͰ-Ͽ]*|[Ѐ-ӿͰ-Ͽ]+[A-Za-z_]+/);
      if (m) {
        n++;
        out.push(finding(path, i, lines[i], m.index, 'hidden-homoglyph', 'hidden', 'medium', '英字にそっくりな別の文字（ホモグリフ）',
          `「${m[0]}」にキリル文字やギリシャ文字が混ざっています。見た目は同じでも別物の名前やURLを作る手口です。`, {}));
      }
    }
  }

  // ---------------------------------------------------------------------------
  // バイナリ判定
  // ---------------------------------------------------------------------------
  function detectBinaryKind(bytes) {
    if (!bytes || bytes.length < 4) return null;
    const b = bytes;
    if (b[0] === 0x4D && b[1] === 0x5A) return 'Windows 実行ファイル (EXE/DLL)';
    if (b[0] === 0x7F && b[1] === 0x45 && b[2] === 0x4C && b[3] === 0x46) return 'Linux 実行ファイル (ELF)';
    const be = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    if ([0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE].includes(be)) return 'macOS 実行ファイル (Mach-O)';
    if (be === 0xCAFEBABE && b[7] < 45) return 'macOS ユニバーサル実行ファイル';
    if (b[0] === 0x23 && b[1] === 0x21) return null; // shebang はテキスト
    return null;
  }

  function isProbablyBinary(bytes) {
    const n = Math.min(bytes.length, 8000);
    for (let i = 0; i < n; i++) if (bytes[i] === 0) return true;
    return false;
  }

  // ---------------------------------------------------------------------------
  // 共通
  // ---------------------------------------------------------------------------
  function finding(file, lineIdx, line, col, id, cat, sev, title, desc, extra) {
    return { file, line: lineIdx + 1, col, lineText: line == null ? '' : String(line), id, cat, sev, title, desc, matchLen: 0, ...extra };
  }

  function scanText(path, text) {
    const out = [];
    const lines = text.split(/\r\n|\r|\n/);

    for (const rule of LINE_RULES) {
      let count = 0, extra = 0;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 200000) continue;
        const m = line.match(rule.re);
        if (!m) continue;
        if (rule.filter && !rule.filter(m, line)) continue;
        if (count >= LINE_HIT_LIMIT) { extra++; continue; }
        count++;
        const f = finding(path, i, line, m.index, rule.id, rule.cat, rule.sev, rule.title, rule.desc, {});
        f.matchLen = m[0].length;
        out.push(f);
      }
      if (extra) {
        const last = out[out.length - 1];
        last.more = extra;
      }
    }

    scanHiddenChars(path, lines, out);
    scanHomoglyph(path, lines, out);
    scanHiddenMarkup(path, text, lines, out);
    scanObfuscationStats(path, text, lines, out);
    scanAutorunConfigs(path, text, lines, out);
    const base = path.split(/[\\/]/).pop().toLowerCase();
    if (base === 'package.json') scanPackageJson(path, text, lines, out);
    if (/^requirements.*\.txt$/.test(base)) scanRequirements(path, text, lines, out);

    // AIエージェントが自動で読む指示ファイルでのインジェクションは格上げ
    if (/^(claude\.md|agents\.md|\.cursorrules|\.windsurfrules|gemini\.md|copilot-instructions\.md)$/.test(base) || /\.cursor\/rules\//.test(path)) {
      for (const f of out) {
        if (f.cat === 'injection' && f.sev !== 'critical') {
          f.sev = SEV[f.sev].rank >= 3 ? 'critical' : 'high';
          f.desc += '（このファイルはAIエージェントが自動で読み込むため、影響が大きくなります）';
        }
      }
    }

    return out;
  }

  function scanBinary(path, bytes) {
    const kind = detectBinaryKind(bytes);
    if (!kind) return [];
    return [finding(path, -1, '', -1, 'bin-exec', 'code', 'high', `実行ファイル（${kind}）が含まれています`,
      'ソースコードではなくコンパイル済みのプログラムです。中身を検証できないため、出どころが確かでない限り実行しないでください。', {})];
  }

  function summarize(findings) {
    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    const byCat = {};
    const perRule = {};
    let score = 0;
    for (const f of findings) {
      bySev[f.sev]++;
      byCat[f.cat] = (byCat[f.cat] || 0) + 1;
      const key = f.id;
      const w = SEV[f.sev].weight;
      perRule[key] = (perRule[key] || 0) + 1;
      // 同じルールの繰り返しは加点を逓減させる
      if (perRule[key] <= 3) score += w / perRule[key];
    }
    score = Math.round(score);
    let level;
    if (bySev.critical > 0 || score >= 60) level = 'danger';
    else if (bySev.high > 0 || score >= 16) level = 'warn';
    else if (findings.length > 0) level = 'info';
    else level = 'safe';
    return { score, level, bySev, byCat, total: findings.length };
  }

  const Scanner = { scanText, scanBinary, summarize, isProbablyBinary, SEV, CAT, LINE_RULES, isInvisible };

  if (typeof module !== 'undefined' && module.exports) module.exports = Scanner;
  else root.Scanner = Scanner;
})(typeof globalThis !== 'undefined' ? globalThis : this);
