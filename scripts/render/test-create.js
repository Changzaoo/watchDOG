const fetch = global.fetch;
(async () => {
  try {
    const payload = {
      type: 'web_service',
      name: `watchdog-test-${Date.now().toString().slice(-4)}`,
      ownerId: 'tea-d8l38hu7r5hc739j4c4g',
      repo: { provider: 'github', name: 'Changzaoo/watchDOG', branch: 'main' },
      serviceDetails: { runtime: 'node' }
    };
    const res = await fetch('https://api.render.com/v1/services', { method: 'POST', headers: { Authorization: 'Bearer ' + process.env.RENDER_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const txt = await res.text();
    console.log('STATUS', res.status, res.statusText);
    console.log(txt);
  } catch (e) {
    console.error('ERR', e);
  }
})();
