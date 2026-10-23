// The proxy Worker's deploy config must keep logging off and point at the
// reviewed source. The privacy page depends on both.
const fs = require('fs');
const path = require('path');
let pass = 0, fail = 0;
const check = (name, ok) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + name); };

const raw = fs.readFileSync(path.join(__dirname, 'wrangler.proxy.jsonc'), 'utf8');
const cfg = JSON.parse(raw.replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1'));
check('targets the proxy Worker', cfg.name === 'cool-sound-6db2riskpass');
check('deploys goplus-proxy-worker.js', cfg.main === 'goplus-proxy-worker.js' && fs.existsSync(path.join(__dirname, cfg.main)));
const o = cfg.observability || {};
check('observability disabled', o.enabled === false);
check('logs disabled', o.logs && o.logs.enabled === false && o.logs.invocation_logs === false);
check('traces disabled', o.traces && o.traces.enabled === false);
check('no Logpush', !cfg.logpush);
check('no Tail Workers', !(cfg.tail_consumers && cfg.tail_consumers.length));
check('dashboard variables are kept', cfg.keep_vars === true);
check('no secrets or keys written into the config', !/GOPLUS_APP_(KEY|SECRET)"\s*:/.test(raw));
check('the D1 binding the code uses is present',
  (cfg.d1_databases || []).some(d => d.binding === 'COUNTS'));
const ignore = fs.readFileSync(path.join(__dirname, '.assetsignore'), 'utf8');
check('the config is not published as a site asset', /^wrangler\.proxy\.jsonc$/m.test(ignore));

console.log(`\n${pass}/${pass + fail} proxy config checks passed`);
process.exit(fail ? 1 : 0);
