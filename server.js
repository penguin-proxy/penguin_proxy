const express = require('express');
const basicAuth = require('express-basic-auth');
const httpProxy = require('http-proxy');
const http = require('http');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// プロキシサーバーの初期化
const proxy = httpProxy.createProxyServer({
    ws: true,
    changeOrigin: true, // ターゲットのホスト名に偽装
    secure: false,      // ターゲットのSSL証明書エラーを無視
    xfwd: false         // 匿名化（IP漏洩防止）
});

// 【リクエスト送信時】 ターゲットのサーバーを騙す（ヘッダー偽装）
proxy.on('proxyReq', (proxyReq, req, res, options) => {
    // 追跡用ヘッダーの削除
    proxyReq.removeHeader('x-forwarded-for');
    proxyReq.removeHeader('x-forwarded-proto');
    proxyReq.removeHeader('x-real-ip');

    // 直リンク防止（ホットリンクプロテクション）やCORSを突破するため、
    // OriginとRefererをターゲット自身のサイトから来たかのように偽装する
    if (options.target && options.target.origin) {
        proxyReq.setHeader('origin', options.target.origin);
        proxyReq.setHeader('referer', options.target.origin + '/');
    }
});

// 【レスポンス受信時】 ブラウザのセキュリティ制限を全解除する
proxy.on('proxyRes', (proxyRes, req, res) => {
    // iframeのブロックや強力なセキュリティ制限をすべて剥がす
    const securityHeaders = [
        'x-frame-options', 'content-security-policy', 'content-security-policy-report-only',
        'x-content-type-options', 'strict-transport-security',
        'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy'
    ];
    securityHeaders.forEach(h => delete proxyRes.headers[h]);

    // CORSをフルオープンにする
    proxyRes.headers['access-control-allow-origin'] = '*';
    proxyRes.headers['access-control-allow-methods'] = 'GET, PUT, PATCH, POST, DELETE, OPTIONS';
    proxyRes.headers['access-control-allow-headers'] = '*';

    // Cookieの最適化（ログイン状態を保持しやすくする）
    const setCookieHeader = proxyRes.headers['set-cookie'];
    if (setCookieHeader) {
        const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
        proxyRes.headers['set-cookie'] = cookies.map(cookie => {
            return cookie.replace(/Domain=[^;]+/i, '')
                         .replace(/SameSite=[^;]+/i, 'SameSite=None; Secure'); 
        });
    }

    // リダイレクト（Location）の自動修正
    if (proxyRes.headers['location']) {
        let location = proxyRes.headers['location'];
        if (location.startsWith('http')) {
            proxyRes.headers['location'] = '/view/' + location;
        } else if (location.startsWith('/')) {
            try {
                const targetUrlStr = req.url.replace(/^\/view\//, '');
                const base = new URL(targetUrlStr);
                proxyRes.headers['location'] = '/view/' + base.origin + location;
            } catch(e) {}
        }
    }
});

// エラーが起きてもサーバーをクラッシュさせない
proxy.on('error', (err, req, res) => {
    console.error('Proxy Error:', err.message);
    if (res && res.writeHead && !res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('通信エラーが発生しました。サイトがブロックしているか、応答していません。');
    }
});

// Basic認証（環境変数対応）
const USERNAME = process.env.PROXY_USER || 'admin';
const PASSWORD = process.env.PROXY_PASS || '1234';

app.use(basicAuth({
    users: { [USERNAME]: PASSWORD },
    challenge: true,
    unauthorizedResponse: '認証が必要です。'
}));

// 【相対リンク修復ミドルウェア】 壊れた画像やCSS、JSを自動修復
app.use((req, res, next) => {
    // 連続した /view//view/ を解消するバグフィックス
    if (req.url.includes('/view//view/')) {
        req.url = req.url.replace(/\/view\//g, '/view/').replace('/view//view/', '/view/');
    }

    if (req.url === '/' || req.url === '/index.html' || req.url.startsWith('/view/')) {
        return next();
    }
    
    // Refererをもとに本来のURLを推測して読み込む
    const referer = req.headers.referer;
    if (referer && referer.includes('/view/')) {
        try {
            const targetUrlStr = referer.split('/view/')[1];
            const base = new URL(targetUrlStr);
            const absoluteTarget = new URL(req.url, base.origin).href;
            
            if (req.headers.accept && req.headers.accept.includes('text/html')) {
                return res.redirect('/view/' + absoluteTarget);
            }
            req.url = '/view/' + absoluteTarget;
        } catch (e) {}
    }
    next();
});

// 静的ファイルの配信
app.use(express.static(path.join(__dirname, 'public')));

// 【メインのプロキシルーティング】
app.all('/view/*', (req, res) => {
    let targetUrlStr = req.url.substring(6); // '/view/' (6文字) を除外
    
    // スラッシュ2つで始まるURL（//example.com等）の自動補完
    if (targetUrlStr.startsWith('//')) {
        targetUrlStr = 'https:' + targetUrlStr;
    }

    if (!targetUrlStr.startsWith('http')) {
        return res.status(400).send('無効なURLです。http:// または https:// から入力してください。');
    }
    
    try {
        const targetUrl = new URL(targetUrlStr);
        // パスとクエリだけを抽出してリクエスト（Google等での400エラー防止）
        req.url = targetUrl.pathname + targetUrl.search;
        proxy.web(req, res, { target: targetUrl.origin });
    } catch (e) {
        if (!res.headersSent) res.status(400).send('URLの解析エラーが発生しました。');
    }
});

// HTTPサーバー作成とWebSocket対応（ゲームやチャット等に必須）
const server = http.createServer(app);
server.on('upgrade', (req, socket, head) => {
    if (req.url.startsWith('/view/')) {
        let targetUrlStr = req.url.substring(6);
        try {
            const targetUrl = new URL(targetUrlStr);
            req.url = targetUrl.pathname + targetUrl.search;
            proxy.ws(req, socket, head, { target: targetUrl.origin });
        } catch (e) {
            socket.destroy();
        }
    }
});

server.listen(PORT, () => {
    console.log(`Penguin Proxy is running on port ${PORT}`);
});
