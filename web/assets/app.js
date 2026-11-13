/* Agent Allowance — shared client logic.
   Read-only chain access, formatting, and renderers used by every page. */

const RPCS = ["https://test.rpc.fastnear.com", "https://rpc.testnet.near.org"];
// Ordinary nodes garbage-collect transactions after a few days. Reading an old
// transaction has to try an archival node first, or the proof stops loading.
const ARCHIVE = ["https://archival-rpc.testnet.fastnear.com",
                 "https://archival-rpc.testnet.near.org"];
const VAULT = "agent-allowance.testnet";
const AGENT = "aa-agent.testnet";
const PAYEE = "payee.agent-allowance.testnet";
const USDC  = "usdc.fakes.testnet";

const ASSETS = {
  near: { label: "NEAR",   dec: 24, method: "request_spend",    token: null,  def: "0.005" },
  usdc: { label: "USDC.e", dec: 6,  method: "request_spend_ft", token: USDC,  def: "2" }
};

const PROOFS = [
  { h:"2UEaarEHrGvi3MbCohmTGF7fEnr4pTXs6JcnK9edXzPr", s:"bot.agent-allowance.testnet",
    t:"Pay an allowlisted payee 0.5 NEAR", v:"a", lab:"ALLOWED", asset:"NEAR" },
  { h:"HAd35gbQuPMe8d8JVzJhmFobgsT7s8igoyqVv7iUWz8y", s:"bot.agent-allowance.testnet",
    t:"Prompt-injected NEAR drain to attacker.testnet", v:"d", lab:"BLOCKED", asset:"NEAR" },
  { h:"2AGh8GW2DoZaPbQkrgew7C5b6DouvD6aVHZkBFF5FknA", s:"bot.agent-allowance.testnet",
    t:"Oversized 5 NEAR transfer, cap is 1", v:"d", lab:"BLOCKED", asset:"NEAR" },
  { h:"GuJRKr2v51koWPfMYKBJCN8upGnP26eowsMPNXjNE9SM", s:AGENT,
    t:"Pay an allowlisted payee 2 USDC.e", v:"a", lab:"ALLOWED", asset:"USDC.e" },
  { h:"5td8rsqQgbsTgjqQ4N8cGTSD4APJwXZo6cWv2aY6iZTT", s:AGENT,
    t:"Prompt-injected stablecoin drain to attacker.testnet", v:"d", lab:"BLOCKED", asset:"USDC.e" }
];

const TOKEN_NAMES = { [USDC]: "USDC.e" };
const tokenName = id => TOKEN_NAMES[id] || id.split(".")[0].toUpperCase();

const esc = t => String(t).replace(/[&<>"]/g,
  m => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[m]));
const fmt = (v, d) => (Number(v) / 10 ** d).toLocaleString(undefined,
  { maximumFractionDigits: d > 6 ? 3 : 2 });
const short = h => h.slice(0, 8) + "…";

/** Stamp the footer with the time of the last successful chain read. */
function stamp(text) {
  const el = document.getElementById("updated");
  if (el) el.textContent = text || "updated " + new Date().toLocaleTimeString();
}

/** POST to NEAR RPC, falling back to the next endpoint. Public endpoints
 *  throttle bursts and occasionally hang, so each try is time-boxed and a
 *  refusal is retried elsewhere rather than surfaced. */
async function rpc(payload, endpoints = RPCS) {
  let last;
  for (const ep of endpoints) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 12000);
    try {
      const r = await fetch(ep, { method: "POST", signal: ctl.signal,
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      if (!r.ok) { last = "HTTP " + r.status; continue; }
      const j = await r.json();
      if (j.error) { last = j.error.message; continue; }
      return j.result;
    } catch (e) { last = e.name === "AbortError" ? "timed out" : e.message; }
    finally { clearTimeout(timer); }
  }
  throw new Error(last || "RPC unreachable");
}

/** A transaction and its receipts, however old it is. */
const txStatus = (hash, signer) =>
  rpc({ jsonrpc:"2.0", id:1, method:"tx", params:[hash, signer] }, [...ARCHIVE, ...RPCS]);

async function view(method, args = {}) {
  const res = await rpc({ jsonrpc:"2.0", id:1, method:"query", params:{
    request_type:"call_function", finality:"final", account_id:VAULT,
    method_name:method, args_base64: btoa(JSON.stringify(args)) }});
  return JSON.parse(new TextDecoder().decode(new Uint8Array(res.result)));
}

const eventsFrom = r => (r.receipts_outcome || [])
  .flatMap(o => o.outcome.logs)
  .filter(l => l.includes("EVENT_JSON:"))
  .map(l => JSON.parse(l.split("EVENT_JSON:")[1]));

function renderEvent(ev) {
  const d = ev.data[0];
  const denied = ev.event.includes("denied");
  const cls = denied ? "deny" : "allow";
  const dec = d.token_id ? 6 : 24;
  let o = `<span class="k">event</span>     <span class="${cls}">${esc(ev.event)}</span>\n`;
  if (d.reason)   o += `<span class="k">reason</span>    <span class="${cls}">${esc(d.reason)}</span>\n`;
  if (d.token_id) o += `<span class="k">token</span>     ${esc(d.token_id)}\n`;
  o += `<span class="k">recipient</span> ${esc(d.recipient)}\n`;
  o += `<span class="k">amount</span>    ${fmt(d.amount, dec)}`;
  if (d.memo)     o += `\n<span class="k">memo</span>      <span class="memo">"${esc(d.memo)}"</span>`;
  return o;
}

const statCard = (label, val, cls = "") =>
  `<div class="glass pad stat"><div class="label">${label}</div>
   <div class="val ${cls}">${val}</div></div>`;

function assetBlock(name, dec, p, remaining) {
  const daily = Number(p.daily_cap), left = Number(remaining);
  const used = daily ? Math.min(100, Math.max(0, ((daily - left) / daily) * 100)) : 0;
  const spent = BigInt(p.daily_cap) - BigInt(remaining);
  const unit = `<span class="u">${name}</span>`;
  return `<div class="asset">
    <div class="aname"><span>${name}</span><span class="counts">
      <span class="ok">${p.allowed_count} allowed</span> ·
      <span class="no">${p.denied_count} blocked</span></span></div>
    <div class="rows">
      <div class="row"><span class="k">Per payment, at most</span><span class="v">${fmt(p.per_tx_cap, dec)} ${unit}</span></div>
      <div class="row"><span class="k">Per rolling 24 hours, at most</span><span class="v">${fmt(p.daily_cap, dec)} ${unit}</span></div>
      <div class="row"><span class="k">May pay only</span><span class="v">${p.allowlist.map(esc).join(", ")}</span></div>
      <div class="row"><span class="k">Spent in the current window</span><span class="v">${fmt(spent, dec)} of ${fmt(p.daily_cap, dec)} ${unit}</span></div>
    </div>
    <div class="bar" role="img" aria-label="${Math.round(used)}% of the daily cap spent"><i style="width:${used}%"></i></div></div>`;
}

const renderAgent = s => `<div class="glass pad">
  <div class="aid">${esc(s.agent_id)}</div>
  <div style="margin-bottom:18px">${s.policy.enabled
    ? '<span class="pill ok">Enabled</span>' : '<span class="pill no">Disabled</span>'}</div>
  ${assetBlock("NEAR", 24, s.policy, s.remaining_today)}
  ${(s.tokens || []).map(t => assetBlock(esc(tokenName(t.token_id)), 6, t.policy, t.remaining_today)).join("")}
</div>`;

/** Paint vault stats and agent cards into whichever containers exist. */
async function loadDashboard() {
  const stats = document.getElementById("stats");
  const agents = document.getElementById("agents");
  try {
    const d = await view("dashboard");
    if (stats) {
      let cards = statCard("Available balance", fmt(d.available_balance, 24) + '<span class="u">NEAR</span>');
      for (const t of d.tokens)
        cards += statCard(esc(tokenName(t.token_id)) + " held",
          fmt(t.balance, 6) + '<span class="u">' + esc(tokenName(t.token_id)) + '</span>');
      cards += statCard("Attempts blocked", d.total_denied);
      cards += statCard("Kill switch", d.paused
        ? '<span class="pill no">Pulled — all paused</span>'
        : '<span class="pill ok">Armed — not pulled</span>', "sm");
      stats.innerHTML = cards;
    }
    if (agents) agents.innerHTML = d.agents.length
      ? d.agents.map(renderAgent).join("")
      : '<div class="glass pad"><span class="muted">No agents registered</span></div>';
    stamp();
    return d;
  } catch (e) {
    if (stats) stats.innerHTML =
      `<div class="glass pad"><span class="err">Could not reach NEAR RPC: ${esc(e.message)}</span></div>`;
    stamp("could not reach RPC");
    return null;
  }
}

/** Replay each proof transaction's own event from its chain record. */
async function loadProofs(containerId = "proofs", tagId = "livetag") {
  const box = document.getElementById(containerId);
  if (!box) return;
  box.innerHTML = PROOFS.map((p, i) => `
    <div class="glass pad" style="margin-bottom:14px">
      <div style="display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;align-items:flex-start">
        <div><div style="font-weight:650;font-size:15px">${p.t}</div>
        <div class="live" style="margin-top:6px">${p.asset}</div></div>
        <span class="tag ${p.v}">${p.lab}</span></div>
      <a target="_blank" rel="noopener" style="font-family:var(--mono);font-size:12.5px"
         href="https://testnet.nearblocks.io/txns/${p.h}">${short(p.h)}</a>
      <div class="ev" id="ev${i}">reading from chain…</div></div>`).join("");
  // Each lookup is independent, so they run together; a slow or failed one
  // never holds up the others.
  const done = await Promise.all(PROOFS.map(async (p, i) => {
    const el = document.getElementById("ev" + i);
    try {
      const evs = eventsFrom(await txStatus(p.h, p.s));
      if (evs.length) { el.innerHTML = evs.map(renderEvent).join("\n"); return true; }
      el.textContent = "no events found";
    } catch { el.textContent = "could not reach RPC — open the transaction link instead"; }
    return false;
  }));
  const ok = done.filter(Boolean).length;
  const tag = document.getElementById(tagId);
  if (tag) {
    if (ok === PROOFS.length) { tag.textContent = "✓ read live from chain"; tag.className = "live on"; }
    else tag.textContent = "";
  }
  stamp(ok ? null : "could not reach RPC");
}

/** The two-gate pipeline, shared by the overview and the attack console.
 *  Each node takes a state — "", "run", "pass", "stop" or "skip" — and a note. */
const PIPE = [
  { id: "key",   k: "Step 1",          t: "Agent key" },
  { id: "net",   k: "Gate 1 · protocol", t: "NEAR network" },
  { id: "vault", k: "Gate 2 · contract", t: "Vault policy" },
  { id: "money", k: "Outcome",         t: "Money moves" }
];
function pipeHTML(notes = {}, cls = "") {
  return `<div class="pipe ${cls}">` + PIPE.map((n, i) =>
    (i ? '<div class="link" aria-hidden="true"></div>' : "") +
    `<div class="node ${n.id}" id="pipe-${n.id}"><span class="mk" aria-hidden="true"></span>
       <div class="nk">${n.k}</div><div class="nt">${n.t}</div>
       <div class="nn">${notes[n.id] || ""}</div></div>`).join("") + "</div>";
}
function setPipe(states, notes = {}) {
  for (const n of PIPE) {
    const el = document.getElementById("pipe-" + n.id);
    if (!el) continue;
    el.className = `node ${n.id} ${states[n.id] || ""}`;
    el.querySelector(".mk").textContent =
      ({ pass: "✓", stop: "✕", skip: "–" })[states[n.id]] || "";
    if (n.id in notes) el.querySelector(".nn").innerHTML = notes[n.id];
  }
}

/** Mark the current page in the nav. */
function markNav() {
  const here = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav-links a").forEach(a => {
    if ((a.getAttribute("href") || "") === here) a.classList.add("on");
  });
}
document.addEventListener("DOMContentLoaded", markNav);
