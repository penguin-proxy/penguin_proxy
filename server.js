const express = require('express');
const basicAuth = require('express-basic-auth');
const httpProxy = require('http-proxy');
const http = require('http');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// プロキシの作成 (IPアドレス隠蔽のための設定を含む)
const proxy = httpProxy.createProxyServer({
    ws: true,
    changeOrigin: true,
    secure: false,
    xfwd: false // 匿名化: X-Forwarded-For を無効化
});

// リクエスト送信時の処理（匿名性の確保）
proxy.on('proxyReq', (proxyReq, req, res, options) => {
    proxyReq.removeHeader('x-forwarded-for');
    proxyReq.removeHeader('x-forwarded-proto');
    proxyReq.removeHeader('x-real-ip');
});

// レスポンス受信時の処理（セキュリティヘッダーの解除とCookieの最適化）
proxy.on('proxyRes', (proxyRes, req, res) => {
    // iFrameブロックとHSTSの解除
    delete proxyRes.headers['x-frame-options'];
    delete proxyRes.headers['content-security-policy'];
    delete proxyRes.headers['x-content-type-options'];
    delete proxyRes.headers['strict-transport-security'];

    // CORSエラー防止
    proxyRes.headers['access-control-allow-origin'] = '*';

    // Cookieの自動書き換え（ログイン状態の維持をサポート）
    const setCookieHeader = proxyRes.headers['set-cookie'];
    if (setCookieHeader) {
        if (Array.isArray(setCookieHeader)) {
            proxyRes.headers['set-cookie'] = setCookieHeader.map(cookie => {
                return cookie.replace(/Domain=[^;]+/i, '')
                             .replace(/Secure/i, '')
                             .replace(/SameSite=[^;]+/i, 'SameSite=Lax');
            });
        }
    }

    // リダイレクトの追従処理
    if (proxyRes.headers['location']) {
        const location = proxyRes.headers['location'];
        if (location.startsWith('http')) {
            proxyRes.headers['location'] = '/proxy/' + location;
        } else if (location.startsWith('/')) {
            const targetUrl = req.url.replace(/^\/proxy\//, '');
            try {
                const base = new URL(targetUrl);
                proxyRes.headers['location'] = '/proxy/' + base.origin + location;
            } catch(e) {}
        }
    }
});

// エラーハンドリング
proxy.on('error', (err, req, res) => {
    console.error('Proxy Error:', err.message);
    if (res && res.writeHead) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('通信エラーが発生しました。対象サイトが応答していません。');
    }
});

// パスワード認証設定（環境変数対応。デフォルトは admin / 1234）
const USERNAME = process.env.PROXY_USER || 'admin';
const PASSWORD = process.env.PROXY_PASS || '1234';

app.use(basicAuth({
    users: { [USERNAME]: PASSWORD },
    challenge: true,
    unauthorizedResponse: '認証が必要です。'
}));

// 相対リンクの自動修復機能（サイト内の画像やリンクが壊れるのを防ぐ）
app.use((req, res, next) => {
    if (req.url === '/' || req.url === '/index.html' || req.url.startsWith('/proxy/')) {
        return next();
    }
    const referer = req.headers.referer;
    if (referer && referer.includes('/proxy/')) {
        const targetUrlStr = referer.split('/proxy/')[1];
        try {
            const base = new URL(targetUrlStr);
            const absoluteTarget = base.origin + req.url;
            if (req.headers.accept && req.headers.accept.includes('text/html')) {
                return res.redirect('/proxy/' + absoluteTarget);
            }
            req.url = '/proxy/' + absoluteTarget;
        } catch (e) {}
    }
    next();
});

// UI（画面）の配信
app.use(express.static(path.join(__dirname, 'public')));

// メインのプロキシ処理
app.all('/proxy/*', (req, res) => {
    const targetUrl = req.url.replace(/^\/proxy\//, '');
    if (!targetUrl.startsWith('http')) {
        return res.status(400).send('無効なURLです。http:// または https:// から入力してください。');
    }
    proxy.web(req, res, { target: targetUrl });
});

// HTTPサーバーの作成とWebSocket（リアルタイム通信）の中継
const server = http.createServer(app);
server.on('upgrade', (req, socket, head) => {
    if (req.url.startsWith('/proxy/')) {
        const targetUrl = req.url.replace(/^\/proxy\//, '');
        proxy.ws(req, socket, head, { target: targetUrl });
    }
});

server.listen(PORT, () => {
    console.log(`Penguin Proxy is running on port ${PORT}`);
});
