// The page: form, run, results, export. All text from the network or the
// file system is inserted with textContent, never as markup.

import { SETTINGS, MAX_REQUESTS } from "./config.js";
import * as plan from "./plan.js";
import * as rs from "./rangespec.js";
import { parseTarget, runProbe } from "./probe.js";
import { fileReference } from "./compare.js";
import { buildReport, secretsIn, serialize, reportFileName, summarize, runFindingsOf } from "./report.js";
import { formatBytes } from "./util.js";

const $ = (id) => document.getElementById(id);

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  if (props.class) n.className = props.class;
  if (props.text != null) n.textContent = props.text;
  for (const [k, v] of Object.entries(props.attrs ?? {})) n.setAttribute(k, v);
  for (const k of kids) if (k) n.append(k);
  return n;
}

const TONE = { problem: "bad", incomplete: "warn", pass: "pass", violation: "bad", byte_mismatch: "bad", range_ignored: "ign", inconclusive: "warn", transport_error: "warn", skipped: "mute", note: "mute" };
const LABEL = {
  pass: "PASS", violation: "VIOLATION", byte_mismatch: "BYTES DIFFER", range_ignored: "RANGE IGNORED",
  inconclusive: "INCONCLUSIVE", transport_error: "ERROR", skipped: "SKIPPED",
  problem: "PROBLEM", incomplete: "INCOMPLETE",
};
// What a failed check says in its chip: the failure, not just "ERROR".
const FAILURE_LABEL = {
  FETCH_REJECTED: "FETCH REJECTED", REQUEST_TIMEOUT: "TIMEOUT", CANCELLED: "CANCELLED",
  BODY_READ_ERROR: "READ ERROR", HTTP_SERVER_ERROR: "SERVER ERROR",
};
const statusLabel = (c) => (c.status === "transport_error" ? FAILURE_LABEL[c.findings[0]?.id] ?? LABEL.transport_error : LABEL[c.status] ?? c.status.toUpperCase());
const chip = (status, text) => el("span", { class: `chip ${TONE[status] ?? (["pass", "bad", "warn", "ign", "mute"].includes(status) ? status : "mute")}`, text: text ?? LABEL[status] ?? status.toUpperCase() });

const state = { running: false, ctl: null, record: null, ref: null };

// ---- form ----

function readSettings() {
  const num = (id, s) => {
    const v = Number($(id).value);
    return Number.isFinite(v) ? Math.min(s.max, Math.max(s.min, Math.floor(v))) : s.def;
  };
  return {
    probeSize: num("probe-size", SETTINGS.probeSize),
    requestTimeoutS: num("req-timeout", SETTINGS.requestTimeoutS),
    runTimeoutS: num("run-timeout", SETTINGS.runTimeoutS),
  };
}

function refreshForm() {
  const raw = $("url").value.trim();
  const t = raw ? parseTarget(raw) : null;
  if (t?.error || !raw) $("url-error").textContent = t?.error ?? "";
  if (t && !t.error) $("url-error").textContent = "";
  $("url").setAttribute("aria-invalid", t?.error ? "true" : "false");
  const file = $("ref").files[0];
  $("ref-info").textContent = file
    ? `${file.name}: ${formatBytes(file.size)}. Assumed to be byte-identical to the published file; the page cannot check that.`
    : "A local copy of the published file. It is assumed to be byte-identical; the page cannot check that.";
  if (file) $("ref-error").textContent = "";
  $("start").disabled = state.running;
  $("cancel").disabled = !state.running;
  for (const id of ["url", "ref", "probe-size", "req-timeout", "run-timeout"]) $(id).disabled = state.running;
  renderPlan(file);
}

function renderPlan(file) {
  const box = $("plan");
  if (!file) {
    box.hidden = true;
    return;
  }
  const items = [plan.firstByte(), ...plan.build(readSettings().probeSize, plan.sizing(file.size, null))];
  const list = $("plan-list");
  list.replaceChildren(
    ...items.map((it) =>
      el("li", { class: it.skip ? "skipped" : "" },
        el("span", { class: "chip mute", text: it.id }), " ",
        it.skip ? el("code", { text: "not sent" }) : el("code", { text: rs.header(it.spec) }),
        it.skip ? el("span", { class: "hint", text: ` ${it.skip.id}` }) : null),
    ),
  );
  $("plan-note").textContent =
    "Offsets use the reference length until the server reports its own. The CLI also runs " +
    `${plan.OMITTED_CHECKS.join(", ")}; this page does not. It never sends more than ${MAX_REQUESTS} requests.`;
  box.hidden = false;
}

// ---- results ----

function bytesLine(c) {
  const b = c.bytes;
  if (!b) return ["Not compared: no response was read.", "mute"];
  const range = b.scope === "prefix_of_full_response" ? "the start of a full response" : "the requested interval";
  switch (b.outcome) {
    case "match":
      return [`Match: ${formatBytes(b.compared_bytes)} equal reference offsets ${b.expected_first}–${b.expected_first + b.compared_bytes - 1} (${range}).`, "pass"];
    case "mismatch":
      return [
        `Bytes differ: ${b.mismatch_count.toLocaleString("en-US")} of ${formatBytes(b.compared_bytes + (b.bytes_beyond_reference ?? 0))} received are not equal to the reference; the first difference is at offset ${b.first_mismatch_offset}. This is an observation: the reference may be another file or version.`,
        "bad",
      ];
    default:
      return [`Not compared: ${b.reason ?? "no bytes to compare"}.`, "mute"];
  }
}

function evidenceLine(c) {
  if (c.fetch && c.fetch.outcome !== "response") return ["No response was readable.", "mute"];
  const e = c.evidence;
  if (!e) return ["No response.", "mute"];
  if (e.complete === false) {
    return [`Incomplete: ${e.missing.join(", ")} cannot be read by this page. It sees ${e.header_visibility}; the header may be absent or just not exposed.`, "warn"];
  }
  if (e.complete === true) {
    const cr = c.response?.headers.find((h) => h.key === "Content-Range");
    return [cr ? `Complete: Content-Range ${cr.value} is readable.` : "Complete: all headers are readable; none is missing.", "pass"];
  }
  return [`Not needed for status ${c.response?.status}.`, "mute"];
}

function findingNode(f) {
  const n = el("div", { class: "finding" },
    el("div", {}, el("span", { class: "id", text: f.id }), chip(f.kind === "note" ? "note" : f.kind, f.kind.replaceAll("_", " ").toUpperCase())),
    el("div", { text: f.message }));
  if (f.evidence.length) {
    n.append(el("div", { class: "ev", text: f.evidence.map((e) => `${e.key} = ${e.value}`).join("\n") }));
  }
  if (f.limits.length) n.append(el("ul", { class: "lim" }, ...f.limits.map((l) => el("li", { text: l }))));
  return n;
}

function checkNode(c) {
  const li = el("li", { class: "check", attrs: { "data-tone": TONE[c.status] ?? "mute", "data-status": c.status, "data-check": c.id } });
  li.append(el("header", {}, el("h3", {}, c.title + " ", el("small", { text: c.id })), chip(c.status, statusLabel(c))));
  const sent = c.skip ? null : c.response ? `→ ${c.response.status}` : "→ no response";
  li.append(el("p", { class: "req" }, el("code", { text: c.request.range }), c.skip ? ` not sent: ${c.skip.reason}` : ` ${sent}`));
  if (c.skip) return li;

  const dl = el("dl");
  const [bt, bTone] = bytesLine(c);
  const [et, eTone] = evidenceLine(c);
  dl.append(
    el("dt", { text: "Bytes vs reference" }), el("dd", {}, chip(bTone, bTone === "pass" ? "MATCH" : bTone === "bad" ? "DIFFER" : "NOT COMPARED"), " ", bt),
    el("dt", { text: "Protocol evidence" }), el("dd", {}, chip(eTone, eTone === "pass" ? "COMPLETE" : eTone === "warn" ? "INCOMPLETE" : "—"), " ", et),
  );
  if (c.response) {
    const via = c.response.redirected ? `, redirected to ${c.response.final_url}` : "";
    dl.append(el("dt", { text: "Response" }), el("dd", { text: `${c.response.status}, ${c.response.type === "basic" ? "same-origin" : "cross-origin"}${via}` }));
  }
  if (c.fetch?.error) dl.append(el("dt", { text: "fetch() said" }), el("dd", { text: `${c.fetch.error.name}: ${c.fetch.error.message}` }));
  if (c.body) {
    dl.append(el("dt", { text: "Body read" }), el("dd", { text: `${formatBytes(c.body.bytes_read)} of a ${formatBytes(c.body.read_limit)} limit, ${c.body.end_state}${c.body.declared_length != null ? `, declared ${formatBytes(c.body.declared_length)}` : ""}` }));
  }
  if (c.representation && c.representation.encoding !== "not_observable") {
    const enc = { identity: "no content coding", not_observable: "not observable (the browser may have decoded the body)", encoded: `${c.representation.content_encoding}, decoded by the browser` }[c.representation.encoding];
    dl.append(el("dt", { text: "Encoding" }), el("dd", { text: enc }));
  }
  li.append(dl);

  if (c.response?.headers.length) {
    const t = el("table");
    for (const h of c.response.headers) t.append(el("tr", {}, el("th", { text: h.key }), el("td", { text: h.value })));
    li.append(el("details", {}, el("summary", { text: `Headers the page could read (${c.response.headers.length})` }), t,
      el("p", { class: "hint", text: `${c.response.other_header_count} other header(s) readable but not listed here.` })));
  }
  if (c.findings.length) {
    li.append(el("details", {},
      el("summary", { text: `Findings: ${[...new Set(c.findings.map((f) => f.id))].join(", ")}` }), ...c.findings.map(findingNode)));
  }
  if (c.verified.length) li.append(el("details", {}, el("summary", { text: "Claims that held" }), el("ul", {}, ...c.verified.map((v) => el("li", { text: v })))));
  return li;
}

/** One entry per diagnostic ID across the run: where it occurred, said once. */
function groupedFindings(record) {
  const groups = new Map();
  for (const c of record.checks) {
    for (const f of c.findings) {
      const g = groups.get(f.id) ?? { f, checks: [] };
      g.checks.push(c.id);
      groups.set(f.id, g);
    }
  }
  return [...groups.values()];
}

function renderSummary(record) {
  const s = summarize(record.checks, []);
  const box = $("summary");
  const groups = groupedFindings(record);
  const notes = runFindingsOf(record);
  const list = el("ul", { class: "groups" },
    ...groups.map(({ f, checks }) => el("li", {},
      el("span", { class: "id", text: f.id }), " ", chip(f.kind === "note" ? "note" : f.kind, f.kind.replaceAll("_", " ").toUpperCase()),
      ` in ${checks.length === record.checks.length ? "all" : checks.length} check${checks.length === 1 ? "" : "s"}${checks.length === record.checks.length ? "" : ` (${checks.join(", ")})`}: ${f.message}`)),
    ...notes.map((f) => el("li", {}, el("span", { class: "id", text: f.id }), " ", chip("note", "NOTE"), ` ${f.message}. ${f.limits[0] ?? ""}`)));
  box.replaceChildren(
    el("div", { class: "head" }, el("h2", { text: "Result" }), chip(s.result, LABEL[s.result] ?? s.result.toUpperCase().replace("_", " "))),
    el("p", { text: s.headline }),
    el("p", { text: s.axes }),
    el("p", { class: "meta", text: `${record.budget.requests} request(s), ${formatBytes(record.budget.bytes_read)} read, ${record.durationMs} ms${record.interrupted ? ", cancelled" : ""}.` }),
    groups.length || notes.length ? el("h3", { text: "What was found" }) : null,
    groups.length || notes.length ? list : null,
  );
}

function renderRecord(record) {
  $("results").hidden = false;
  renderSummary(record);
  $("checks").replaceChildren(...record.checks.map(checkNode));
}

// ---- run ----

function showResults() {
  $("results").hidden = false;
  const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
  $("results").scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "start" });
}

async function start(ev) {
  ev.preventDefault();
  if (state.running) return;
  const raw = $("url").value.trim();
  const t = raw ? parseTarget(raw) : { error: "Enter the URL of the file." };
  const file = $("ref").files[0];
  $("url-error").textContent = t.error ?? "";
  $("ref-error").textContent = file ? "" : "Choose the reference file.";
  if (t.error) return $("url").focus();
  if (!file) return $("ref").focus();
  state.running = true;
  state.ctl = new AbortController();
  state.ref = fileReference(file);
  $("results").hidden = true;
  $("summary").replaceChildren();
  $("checks").replaceChildren();
  $("download").disabled = true;
  refreshForm();
  const settings = readSettings();
  const checks = [];
  try {
    const record = await runProbe({
      url: t.url,
      ref: state.ref,
      settings,
      signal: state.ctl.signal,
      pageOrigin: location.origin,
      pageProtocol: location.protocol,
      onStart: (it, i, n) => ($("status").textContent = `Check ${i + 1} of ${n}: ${it.title}${it.spec ? ` (${rs.header(it.spec)})` : ""}…`),
      onCheck: (c) => {
        checks.push(c);
        if ($("results").hidden) showResults();
        $("results").hidden = false;
        $("checks").replaceChildren(...checks.map(checkNode));
      },
    });
    state.record = record;
    renderRecord(record);
    $("status").textContent = record.interrupted ? "Cancelled. The checks not yet sent are listed as skipped." : "Done.";
    $("download").disabled = false;
    $("start").textContent = "Run again";
    showResults();
    $("summary").focus({ preventScroll: true });
  } catch (e) {
    $("status").textContent = `The run stopped unexpectedly: ${e?.message ?? e}`;
  } finally {
    state.running = false;
    state.ctl = null;
    refreshForm();
  }
}

// ---- export ----

function save(redact) {
  const text = serialize(buildReport(state.record, { redact }));
  const blob = new Blob([text], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = reportFileName();
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
  $("status").textContent = `Report saved as ${a.download}${redact ? " with a redacted URL" : ""}.`;
}

function exportReport() {
  if (!state.record) return;
  const secrets = secretsIn(state.record);
  if (secrets.queryNames.length === 0) return save(false);
  $("export-names").textContent = secrets.queryNames.slice(0, 6).join(", ") + (secrets.queryNames.length > 6 ? ", …" : "");
  const d = $("export-dialog");
  d.showModal();
  $("export-redacted").focus();
}

function wireDialog() {
  const d = $("export-dialog");
  $("export-redacted").addEventListener("click", () => { d.close(); save(true); });
  $("export-full").addEventListener("click", () => { d.close(); save(false); });
  $("export-cancel").addEventListener("click", () => d.close());
}

// ---- wiring ----

$("probe-form").addEventListener("submit", start);
$("cancel").addEventListener("click", () => state.ctl?.abort());
$("download").addEventListener("click", exportReport);
for (const id of ["url", "ref", "probe-size"]) $(id).addEventListener("input", refreshForm);
$("ref").addEventListener("change", refreshForm);
const form = $("probe-form");
form.addEventListener("dragover", (e) => {
  if (state.running || !e.dataTransfer?.types.includes("Files")) return;
  e.preventDefault();
  form.classList.add("dropping");
});
form.addEventListener("dragleave", (e) => {
  if (!form.contains(e.relatedTarget)) form.classList.remove("dropping");
});
form.addEventListener("drop", (e) => {
  form.classList.remove("dropping");
  if (state.running || !e.dataTransfer?.files.length) return;
  e.preventDefault();
  $("ref").files = e.dataTransfer.files;
  refreshForm();
});
wireDialog();
refreshForm();
