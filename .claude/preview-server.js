// Локальный статический сервер только для визуальной проверки вёрстки.
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.svg': 'image/svg+xml' };

http
  .createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]);

    // /mock/... serves the real index.html with a window.zapret stub spliced
    // in right before renderer.js, so the app renders with fake-but-realistic
    // data instead of throwing on the missing Electron preload bridge.
    if (rel === '/src/mock' || rel === '/src/mock/') {
      const html = fs.readFileSync(path.join(ROOT, 'src/index.html'), 'utf8');
      const mockJs = fs.readFileSync(path.join(__dirname, 'mock-zapret.js'), 'utf8');
      const withMock = html.replace(
        '<script src="renderer.js"></script>',
        `<script>${mockJs}</script>\n<script src="renderer.js"></script>`
      );
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(withMock);
      return;
    }

    const file = path.join(ROOT, rel === '/' ? 'src/index.html' : rel);
    if (!file.startsWith(ROOT)) {
      res.writeHead(403).end();
      return;
    }
    fs.readFile(file, (err, buf) => {
      if (err) {
        res.writeHead(404).end('not found');
        return;
      }
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  })
  .listen(4174, () => console.log('preview on http://localhost:4174'));
