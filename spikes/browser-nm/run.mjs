// usage: node run.mjs <label> <exe> <mode: load|policy> <userDataDir>
import { chromium } from 'playwright-core';
import fs from 'node:fs';
const [label, exe, mode, udd] = process.argv.slice(2);
const ext = new URL('./ext', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const args = ['--no-first-run', '--no-default-browser-check'];
if (mode === 'load') args.push(`--load-extension=${ext}`, `--disable-extensions-except=${ext}`, '--disable-features=DisableLoadExtensionCommandLineSwitch');
const ctx = await chromium.launchPersistentContext(udd, { executablePath: exe, headless: false, args, ignoreDefaultArgs: ['--disable-extensions', '--disable-component-extensions-with-background-pages'] });
await new Promise(r => setTimeout(r, 25000));
const out = { label, mode };
out.serviceWorkers = ctx.serviceWorkers().map(w => w.url());
try {
  const p = await ctx.newPage();
  await p.goto(mode === 'policy' ? 'chrome://policy' : 'chrome://version');
  await p.waitForTimeout(3000);
  out.pageText = (await p.evaluate(() => document.body.innerText)).slice(0, 3000);
  await p.goto('chrome://extensions-internals').catch(() => {});
  await p.waitForTimeout(1500);
  out.extInternals = (await p.evaluate(() => document.body.innerText).catch(() => '')).slice(0, 1500);
} catch (e) { out.pageErr = String(e); }
fs.writeFileSync(`result-${label}.json`, JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));
await ctx.close();
