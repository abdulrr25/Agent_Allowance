/* Agent Allowance — shared client logic.
   Read-only chain access, formatting, and renderers used by every page. */

const RPCS = ["https://rpc.testnet.near.org", "https://test.rpc.fastnear.com"];
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

const esc = t => String(t).replace(/[&<>]/g, m => ({ "&":"&amp;","<":"&lt;",">":"&gt;" }[m]));
const fmt = (v, d) => (Number(v) / 10 ** d).toLocaleString(undefined,
  { maximumFractionDigits: d > 6 ? 3 : 2 });
const short = h => h.slice(0, 8) + "…";

/** POST to NEAR RPC, falling back to a second endpoint. Public endpoints
 *  throttle bursts, so a refusal is retried elsewhere rather than surfaced. */
async function rpc(payload) {
  let last;
  for (const ep of RPCS) {
    try {
      const r = await fetch(ep, { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      if (!r.ok) { last = "HTTP " + r.status; continue; }
      const j = await r.json();
      if (j.error) { last = j.error.message; continue; }
      return j.result;
    } catch (e) { last = e.message; }
  }
  throw new Error(last || "RPC unreachable");
}

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
  return `<div class="asset">
    <div class="aname"><span>${name}</span><span class="counts">
      <span class="ok">${p.allowed_count} allowed</span> ·
      <span class="no">${p.denied_count} blocked</span></span></div>
    <div class="rows">
      <div class="row"><span class="k">Per-transaction cap</span><span class="v">${fmt(p.per_tx_cap, dec)}</span></div>
      <div class="row"><span class="k">Daily cap</span><span class="v">${fmt(p.daily_cap, dec)}</span></div>
      <div class="row"><span class="k">Allowed recipients</span><span class="v">${p.allowlist.join(", ")}</span></div>
      <div class="row"><span class="k">Remaining today</span><span class="v">${fmt(remaining, dec)} / ${fmt(p.daily_cap, dec)}</span></div>
    </div>
    <div class="bar"><i style="width:${used}%"></i></div></div>`;
}

const renderAgent = s => `<div class="glass pad">
  <div class="aid">${s.agent_id}</div>
  <div style="margin-bottom:18px">${s.policy.enabled
    ? '<span class="pill ok">Enabled</span>' : '<span class="pill no">Disabled</span>'}</div>
  ${assetBlock("NEAR", 24, s.policy, s.remaining_today)}
  ${(s.tokens || []).map(t => assetBlock(t.token_id, 6, t.policy, t.remaining_today)).join("")}
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
        cards += statCard(t.token_id.split(".")[0].toUpperCase() + " held",
          fmt(t.balance, 6) + '<span class="u">' + t.token_id.split(".")[0] + '</span>');
      cards += statCard("Attempts blocked", d.total_denied);
      cards += statCard("Kill switch", d.paused
        ? '<span class="pill no">Paused</span>' : '<span class="pill ok">Active</span>', "sm");
      stats.innerHTML = cards;
    }
    if (agents) agents.innerHTML = d.agents.length
      ? d.agents.map(renderAgent).join("")
      : '<div class="glass pad"><span class="muted">No agents registered</span></div>';
    const stamp = document.getElementById("updated");
    if (stamp) stamp.textContent = "updated " + new Date().toLocaleTimeString();
    return d;
  } catch (e) {
    if (stats) stats.innerHTML =
      `<div class="glass pad"><span class="err">Could not reach NEAR RPC: ${esc(e.message)}</span></div>`;
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
         href="https://explorer.testnet.near.org/transactions/${p.h}">${short(p.h)}</a>
      <div class="ev" id="ev${i}">reading from chain…</div></div>`).join("");
  let ok = 0;
  for (let i = 0; i < PROOFS.length; i++) {
    const el = document.getElementById("ev" + i);
    try {
      const r = await rpc({ jsonrpc:"2.0", id:1, method:"tx", params:[PROOFS[i].h, PROOFS[i].s] });
      const evs = eventsFrom(r);
      if (evs.length) { el.innerHTML = evs.map(renderEvent).join("\n"); ok++; }
      else el.textContent = "no events found";
    } catch (e) { el.textContent = "could not reach RPC — open the transaction link instead"; }
    await new Promise(r => setTimeout(r, 320));
  }
  const tag = document.getElementById(tagId);
  if (tag) {
    if (ok === PROOFS.length) { tag.textContent = "✓ read live from chain"; tag.className = "live on"; }
    else tag.textContent = "";
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
