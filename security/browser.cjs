const { chromium } = require('playwright');

(async () => {
  const server = await chromium.launchServer({
    host: '0.0.0.0', port: 3000, wsPath: '/scamtrace',
    headless: true, chromiumSandbox: true,
    proxy: {server: 'http://proxy:8080', bypass: '<-loopback>'},
    args: ['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'],
  });
  console.log('Isolated browser ready');
  process.on('SIGTERM', async () => { await server.close(); process.exit(0); });
})().catch(error => { console.error(error); process.exit(1); });
