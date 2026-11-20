const HOST = "com.kontext.spike";
const send = (o) => new Promise(res => chrome.runtime.sendNativeMessage(HOST, o, r => res({r, err: chrome.runtime.lastError && chrome.runtime.lastError.message})));
async function run() {
  const self = await chrome.management.getSelf();
  const a = await send({kind: "hello", installType: self.installType, id: self.id, ua: navigator.userAgent});
  const all = await chrome.management.getAll();
  await send({kind: "inventory", n: all.length, ext: all.map(e => [e.id, e.name, e.installType])});
  const port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener(m => { if (m.kind === "pong") send({kind: "port_ok", rtt_ms: Date.now() - m.sent}); });
  port.onDisconnect.addListener(() => chrome.storage.local.set({disc: chrome.runtime.lastError && chrome.runtime.lastError.message}));
  port.postMessage({kind: "ping", sent: Date.now()});
  chrome.storage.local.set({hello: a});
}
chrome.runtime.onInstalled.addListener(run);
chrome.runtime.onStartup.addListener(run);
