const express = require('express');
const basicAuth = require('express-basic-auth');
const httpProxy = require('http-proxy');
const http = require('http');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;


const proxy = httpProxy.createProxyServer({
    ws: true,
    changeOrigin: true,
    secure: false,
    xfwd: false 
});

proxy.on('proxyReq', (proxyReq, req, res, options) => {
    proxyReq.removeHeader('x-forwarded-for');
    proxyReq.removeHeader('x-forwarded-proto');
    proxyReq.removeHeader('x-real-ip');
});

proxy.on('proxyRes', (proxyRes, req, res) => {
    delete proxyRes.headers['x-frame-options'];
    delete proxyRes.headers['content-security-policy'];
    delete proxyRes.headers['x-content-type-options'];
    delete proxyRes.headers['strict-transport-security'];
    proxyRes.headers['access-control-allow-origin'] = '*';

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

    
    if (proxyRes.headers['location']) {
        const location = proxyRes.headers['location'];
        if (location.startsWith('http')) {
            proxyRes.headers['location'] = '/view/' + location;
        } else if (location.startsWith('/')) {
            const targetUrl = req.url.replace(/^\/view\//, '');
            try {
                const base = new URL(targetUrl);
                proxyRes.headers['location'] = '/view/' + base.origin + location;
            } catch(e) {}
        }
    }
});

proxy.on('error', (err, req, res) => {
    console.error('Proxy Error:', err.message);
    if (res && res.writeHead) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('通信エラーが発生しました。');
    }
});

const USERNAME = process.env.PROXY_USER || 'admin';
const PASSWORD = process.env.PROXY_PASS || '1234';

app.use(basicAuth({
    users: { [USERNAME]: PASSWORD },
    challenge: true,
    unauthorizedResponse: '認証が必要です。'
}));


app.use((req, res, next) => {
    if (req.url === '/' || req.url === '/index.html' || req.url.startsWith('/view/')) {
        return next();
    }
    const referer = req.headers.referer;
    if (referer && referer.includes('/view/')) {
        const targetUrlStr = referer.split('/view/')[1];
        try {
            const base = new URL(targetUrlStr);
            const absoluteTarget = base.origin + req.url;
            if (req.headers.accept && req.headers.accept.includes('text/html')) {
                return res.redirect('/view/' + absoluteTarget);
            }
            req.url = '/view/' + absoluteTarget;
        } catch (e) {}
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public')));


app.all('/view/*', (req, res) => {
    const targetUrl = req.url.replace(/^\/view\//, '');
    if (!targetUrl.startsWith('http')) {
        return res.status(400).send('無効なURLです。');
    }
    proxy.web(req, res, { target: targetUrl });
});

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
    if (req.url.startsWith('/view/')) {
        const targetUrl = req.url.replace(/^\/view\//, '');
        proxy.ws(req, socket, head, { target: targetUrl });
    }
});

server.listen(PORT, () => {
    console.log(`Penguin Pro is running on port ${PORT}`);
});
