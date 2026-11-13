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

/** Parse a decimal amount into exact integer base units. String arithmetic,
 *  not floats, so a long or large amount cannot lose precision on its way to
 *  the chain — and a typo gets a readable message instead of a BigInt error. */
function toUnits(str, dec) {
  if (!/^\d+(\.\d+)?$/.test(str))
    throw new Error(`"${str}" is not a valid amount. Enter a positive number, for example 0.005.`);
  const [whole, frac = ""] = str.split(".");
  if (frac.length > dec)
    throw new Error(`Too many decimal places — this asset has ${dec}.`);
  const units = BigInt(whole + frac.padEnd(dec, "0"));
  if (units === 0n) throw new Error("Enter an amount greater than zero.");
  return units;
}

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
    <div class="glass pad">
      <div style="display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;align-items:flex-start">
        <div><h3>${p.t}</h3>
        <div class="small" style="margin-top:6px">${p.asset} · signed by <code>${p.s}</code> ·
          <a target="_blank" rel="noopener"
             href="https://testnet.nearblocks.io/txns/${p.h}">${short(p.h)}</a></div></div>
        <span class="tag ${p.v}">${p.lab}</span></div>
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
  { id: "key",   k: "The agent",       t: "Agent key" },
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

/* ------------------------------------------------------------------
   Hero replay: recorded transactions, played back from their own events.
   Nothing here is scripted copy — each scene is read from the chain first,
   and the window stays on its static first frame if the chain is unreachable.
   ------------------------------------------------------------------ */
const wait = ms => new Promise(r => setTimeout(r, ms));

async function startReplay(rootId = "replay") {
  const root = document.getElementById(rootId);
  if (!root) return;
  const line = root.querySelector(".wline .txt"), caret = root.querySelector(".caret");
  const who = root.querySelector(".who"), src = root.querySelector(".wfoot a");
  const step = n => root.querySelector(`[data-step="${n}"]`);
  const set = (n, state, note) => {
    const el = step(n); el.className = "wstep " + state;
    el.querySelector(".wm").textContent = ({ pass:"✓", stop:"✕", skip:"–" })[state] || (n + 1);
    el.querySelector(".wn").textContent = note || "";
  };
  const scenes = (await Promise.all(PROOFS.map(async p => {
    try { const ev = eventsFrom(await txStatus(p.h, p.s))[0]; return ev ? { p, ev } : null; }
    catch { return null; }
  }))).filter(Boolean);
  if (!scenes.length) return;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  // Lead with the attack, not the happy path.
  scenes.sort((a, b) => a.ev.event.includes("denied") === b.ev.event.includes("denied") ? 0
    : a.ev.event.includes("denied") ? -1 : 1);

  for (let i = 0; ; i = (i + 1) % scenes.length) {
    const { p, ev } = scenes[i], d = ev.data[0], denied = ev.event.includes("denied");
    const amount = fmt(d.amount, d.token_id ? 6 : 24) + " " + (d.token_id ? tokenName(d.token_id) : "NEAR");
    const memo = d.memo || "(no memo)";
    who.textContent = d.agent_id + " ›";
    src.textContent = "tx " + short(p.h); src.href = "https://testnet.nearblocks.io/txns/" + p.h;
    [0, 1, 2, 3].forEach(n => set(n, "", ""));
    line.textContent = ""; caret.hidden = false;
    if (still) line.textContent = memo;
    else for (const ch of memo) { line.textContent += ch; await wait(22); }
    caret.hidden = true;
    await wait(still ? 0 : 500); set(0, "pass", `asks for ${amount} → ${d.recipient}`);
    await wait(still ? 0 : 550); set(1, "pass", "key may call " + (d.token_id ? "request_spend_ft" : "request_spend"));
    await wait(still ? 0 : 650);
    if (denied) { set(2, "stop", d.reason); set(3, "skip", "nothing moved"); }
    else { set(2, "pass", "inside policy"); await wait(still ? 0 : 450); set(3, "pass", amount + " paid"); }
    if (still) return;
    await wait(4200);
  }
}

/* ------------------------------------------------------------------
   Activity: every call the vault has received, newest first, decoded from
   the transactions' own receipts.
   ------------------------------------------------------------------ */
const TXAPI = "https://tx.test.fastnear.com/v0";
const OWNER_CALLS = { add_agent:"registered an agent", update_policy:"changed a policy",
  set_agent_enabled:"toggled an agent", revoke_agent:"revoked an agent",
  set_paused:"used the kill switch", withdraw:"withdrew NEAR", withdraw_ft:"withdrew tokens",
  add_token:"accepted a token", remove_token:"stopped accepting a token",
  set_ft_policy:"set a token policy", revoke_ft_policy:"revoked a token policy",
  ft_on_transfer:"received a token deposit", ft_transfer_call:"deposited tokens into the vault",
  new:"initialised the vault",
  migrate:"migrated the vault" };

async function postJSON(url, body) {
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 15000);
  try {
    const r = await fetch(url, { method:"POST", signal:ctl.signal,
      headers:{ "Content-Type":"application/json" }, body:JSON.stringify(body) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.json();
  } finally { clearTimeout(timer); }
}

const ago = ms => {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return Math.floor(s / 86400) + " d ago";
};

/** Decode one indexed transaction into a feed row. */
function activityRow(t) {
  const tx = t.transaction, call = (tx.actions[0] || {}).FunctionCall;
  if (!call) return null;
  const logs = [t.execution_outcome, ...(t.receipts || []).map(r => r.execution_outcome)]
    .filter(Boolean).flatMap(o => o.outcome.logs || []);
  const evs = logs.filter(l => l.startsWith("EVENT_JSON:")).map(l => {
    try { return JSON.parse(l.slice(11)); } catch { return null; } }).filter(Boolean);
  const when = Number(BigInt(t.execution_outcome.block_timestamp) / 1000000n);
  const base = { hash: tx.hash, signer: tx.signer_id, when, method: call.method_name };
  const spend = evs.find(e => /spend_(allowed|denied)$/.test(e.event));
  if (spend) {
    const d = spend.data[0], denied = spend.event.includes("denied");
    return { ...base, kind: denied ? "d" : "a", agent: d.agent_id, recipient: d.recipient,
      amount: fmt(d.amount, d.token_id ? 6 : 24) + " " + (d.token_id ? tokenName(d.token_id) : "NEAR"),
      reason: d.reason, memo: d.memo };
  }
  if (/^request_spend/.test(call.method_name))
    return { ...base, kind: "f", agent: tx.signer_id };
  return { ...base, kind: "n", note: OWNER_CALLS[call.method_name] || ("called " + call.method_name) };
}

function renderActivity(rows, filter) {
  const shown = rows.filter(r => filter === "all" || r.kind === filter);
  if (!shown.length) return '<div class="glass pad"><span class="muted">Nothing to show for this filter yet.</span></div>';
  return shown.map(r => {
    const tag = { d:'<span class="tag d">Blocked</span>', a:'<span class="tag a">Allowed</span>',
      f:'<span class="tag d">Rejected</span>',
      n:`<span class="tag n">${r.signer === VAULT ? "Owner" : "Other"}</span>` }[r.kind];
    let what;
    if (r.kind === "d" || r.kind === "a")
      what = `<b>${esc(r.agent)}</b> asked to pay <b>${esc(r.amount)}</b> to <b>${esc(r.recipient)}</b>` +
        `<div class="meta">${r.kind === "d" ? "reason · " + esc(r.reason) : "inside policy · transfer scheduled"}</div>` +
        (r.memo ? `<div class="quote">“${esc(r.memo.length > 180 ? r.memo.slice(0, 180) + "…" : r.memo)}”</div>` : "");
    else if (r.kind === "f")
      what = `<b>${esc(r.agent)}</b> called <code>${esc(r.method)}</code> and the call was rejected` +
        `<div class="meta">not a registered agent, or malformed input — nothing was recorded</div>`;
    else what = `<b>${esc(r.signer)}</b> ${esc(r.note)}<div class="meta">${esc(r.method)}</div>`;
    return `<div class="item"><div>${tag}</div><div class="what">${what}</div>
      <div class="when"><span title="${new Date(r.when).toLocaleString()}">${ago(r.when)}</span>
      <a target="_blank" rel="noopener" href="https://testnet.nearblocks.io/txns/${r.hash}">${short(r.hash)}</a></div></div>`;
  }).join("");
}

/** Load the feed into #feed and its counters. Resolves to the decoded rows. */
async function loadActivity(limit = 100) {
  const list = await postJSON(TXAPI + "/account", { account_id: VAULT });
  const hashes = (list.account_txs || []).filter(t => t.is_receiver && t.is_function_call)
    .slice(0, limit).map(t => t.transaction_hash);
  const full = [];
  for (let i = 0; i < hashes.length; i += 20) {
    const part = await postJSON(TXAPI + "/transactions", { tx_hashes: hashes.slice(i, i + 20) });
    full.push(...(part.transactions || []));
  }
  // The indexer can return a transaction more than once; keep the first.
  const seen = new Set();
  const rows = full.map(activityRow).filter(r => r && !seen.has(r.hash) && seen.add(r.hash));
  return { total: list.txs_count, rows: rows.sort((a, b) => b.when - a.when) };
}

/** Copy buttons: any element with data-copy copies the text of that target. */
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  const el = document.getElementById(b.dataset.copy);
  try {
    await navigator.clipboard.writeText(el ? el.textContent : "");
    const was = b.textContent; b.textContent = "copied";
    setTimeout(() => { b.textContent = was; }, 1400);
  } catch { /* clipboard unavailable — the text is still selectable */ }
});

/** Navigation: mark the current page and wire the small-screen menu. */
function initNav() {
  const here = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav-links a").forEach(a => {
    if ((a.getAttribute("href") || "") === here) { a.classList.add("on"); a.setAttribute("aria-current", "page"); }
  });
  const menu = document.getElementById("navmenu"), links = document.getElementById("navlinks");
  if (menu && links) menu.addEventListener("click", () => {
    const open = links.classList.toggle("open");
    menu.setAttribute("aria-expanded", String(open));
  });
}
document.addEventListener("DOMContentLoaded", initNav);
