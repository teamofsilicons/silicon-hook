import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
const gateway = new URL(process.env.VITE_HOOK_GATEWAY_ORIGIN || 'https://backend.hook.teamofsilicons.com');
if (gateway.protocol !== 'https:' || gateway.pathname !== '/' || gateway.username || gateway.password || gateway.search || gateway.hash) throw new Error('An exact HTTPS gateway origin is required');
const ws = new URL(gateway); ws.protocol = 'wss:';
const output = '.vercel/output';
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await cp('dist/client', `${output}/static`, { recursive: true });
await writeFile(`${output}/config.json`, JSON.stringify({
  version: 3,
  routes: [
    { src: '/(.*)', headers: {
      'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
      'Content-Security-Policy': `default-src 'self'; connect-src 'self' ${gateway.origin} ${ws.origin}; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    }, continue: true },
    { src: '/assets/(.*)', headers: {'Cache-Control': 'public, max-age=31536000, immutable'}, continue: true },
    { handle: 'filesystem' },
    { src: '/(.*)', dest: '/index.html', headers: {'Cache-Control': 'no-store'} }
  ]
}, null, 2));
