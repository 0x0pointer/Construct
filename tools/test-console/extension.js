// Construct Test Console: one webview page that explains each test tier, runs it as the
// matching .vscode/tasks.json task, and opens the right output (terminal, log, report,
// dashboard). The panel holds no test logic: every button is a make target.
"use strict";

const vscode = require("vscode");
const fs = require("fs");
const path = require("path");

let panel;

function root() {
  const folders = vscode.workspace.workspaceFolders;
  return folders && folders.length ? folders[0].uri.fsPath : undefined;
}

function startupVerdict() {
  const r = root();
  if (!r) return null;
  const log = path.join(r, "work", "startup-tests.log");
  try {
    const lines = fs.readFileSync(log, "utf8").split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      const m = lines[i].match(/^Startup tests: (PASSED|FAILED)/);
      if (m) return m[1];
    }
    return "RUNNING";
  } catch {
    return null;
  }
}

function latestEvalFile(name) {
  const r = root();
  if (!r) return undefined;
  const evals = path.join(r, "work", "kind", "work", "evals");
  let runs;
  try {
    runs = fs.readdirSync(evals);
  } catch {
    return undefined;
  }
  const candidates = runs
    .map((d) => path.join(evals, d, name))
    .filter((f) => fs.existsSync(f))
    .map((f) => ({ f, t: fs.statSync(f).mtimeMs }))
    .sort((a, b) => b.t - a.t);
  return candidates.length ? candidates[0].f : undefined;
}

function runTask(label) {
  return vscode.commands.executeCommand("workbench.action.tasks.runTask", label);
}

async function openPort(port) {
  const external = await vscode.env.asExternalUri(vscode.Uri.parse(`http://localhost:${port}`));
  return vscode.env.openExternal(external);
}

async function openFile(relative, preview) {
  const r = root();
  if (!r) return;
  const uri = vscode.Uri.file(path.join(r, relative));
  if (!fs.existsSync(uri.fsPath)) {
    vscode.window.showInformationMessage(`${relative} does not exist yet.`);
    return;
  }
  if (preview) return vscode.commands.executeCommand("markdown.showPreview", uri);
  return vscode.window.showTextDocument(uri);
}

async function onMessage(msg) {
  switch (msg.cmd) {
    case "run":
      return runTask(msg.arg);
    case "openStartupLog":
      return openFile(path.join("work", "startup-tests.log"));
    case "openEvalReport": {
      const report = latestEvalFile("report.md");
      if (!report) {
        vscode.window.showInformationMessage(
          "No eval report yet. Reports appear in work/kind/work/evals/<run>/report.md once a kind eval finishes."
        );
        return;
      }
      return vscode.commands.executeCommand("markdown.showPreview", vscode.Uri.file(report));
    }
    case "openEvalLog": {
      const log = latestEvalFile("eval.log");
      if (!log) {
        vscode.window.showInformationMessage("No eval log yet: start an eval first.");
        return;
      }
      return vscode.window.showTextDocument(vscode.Uri.file(log));
    }
    case "kindDashboard":
      await runTask("construct: kind dashboard port-forward");
      // give kubectl port-forward a moment to bind before the browser opens
      setTimeout(() => openPort(8082), 2000);
      return;
    case "openPort":
      return openPort(msg.arg);
    case "refresh":
      if (panel) panel.webview.postMessage({ verdict: startupVerdict() });
      return;
  }
}

function tierRow(title, blurb, task) {
  return `<div class="row">
    <div class="text"><b>${title}</b><br><span class="blurb">${blurb}</span></div>
    <button data-cmd="run" data-arg="${task}">&#9654;&nbsp;Run</button>
  </div>`;
}

function html(webview) {
  const nonce = Math.random().toString(36).slice(2);
  const csp = `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';`;
  return `<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); max-width: 760px; padding: 0 16px; }
  h1 { font-size: 1.5em; margin-bottom: 0.2em; }
  .card { background: var(--vscode-editorWidget-background); border: 1px solid var(--vscode-editorWidget-border, transparent);
          border-radius: 6px; padding: 12px 16px; margin: 14px 0; }
  .card h2 { font-size: 1.1em; margin: 0 0 4px; }
  .lead, .blurb { color: var(--vscode-descriptionForeground); }
  .row { display: flex; align-items: center; gap: 12px; padding: 7px 0; border-top: 1px solid var(--vscode-editorWidget-border, #0003); }
  .row:first-of-type { border-top: none; }
  .row .text { flex: 1; }
  button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none;
           border-radius: 3px; padding: 5px 12px; cursor: pointer; white-space: nowrap; }
  button:hover { background: var(--vscode-button-hoverBackground); }
  button.secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
  .badge { font-weight: bold; padding: 2px 10px; border-radius: 10px; }
  .PASSED { background: #2ea04326; color: #3fb950; }
  .FAILED { background: #f8514926; color: #f85149; }
  .RUNNING, .UNKNOWN { background: #d2992226; color: #d29922; }
  code { font-family: var(--vscode-editor-font-family); }
</style>
</head>
<body>
  <h1>Construct Test Console</h1>
  <p class="lead">Every button is a <code>make</code> target, run as a VS Code task (same list as
  <i>Terminal &rarr; Run Task&hellip;</i>). Output streams into the terminal panel that opens.
  The tiers are ordered: each one trusts what the previous one proved.</p>

  <div class="card">
    <h2>Startup check <span id="verdict" class="badge UNKNOWN">&hellip;</span></h2>
    <p class="blurb"><code>make test</code> and <code>make test-db</code> already ran while this
    Codespace was being created, so there is a verdict before you type anything.</p>
    <div class="row">
      <div class="text">Full output of that run</div>
      <button class="secondary" data-cmd="openStartupLog">Open log</button>
      <button class="secondary" data-cmd="refresh">Refresh</button>
    </div>
  </div>

  <div class="card">
    <h2>Local tiers</h2>
    ${tierRow("Unit tests", "1800+ tests, no database or Docker. ~90&nbsp;s.", "construct: unit tests")}
    ${tierRow("DB tests", "Starts a throwaway Postgres&nbsp;16 in Docker on :55432, runs the <code>db</code> suite against it.", "construct: db tests")}
    ${tierRow("End to end", "The whole pipeline &mdash; API, queue, worker, stages &mdash; with a scripted fake agent. No LLM.", "construct: e2e tests")}
    ${tierRow("Conformance", "Every harness adapter against stub CLIs, offline.", "construct: conformance")}
    ${tierRow("Dynamic replays", "Builds the prsec + workbench images (slow the first time), then replays the reference PoCs in real Docker environments. No LLM.", "construct: dynamic replays")}
  </div>

  <div class="card">
    <h2>Kubernetes tier (kind)</h2>
    <p class="blurb">The whole stack in a local kind cluster: every agent stage and replay as a pod.
    Deploy needs an <code>OPENAI_API_KEY</code> Codespaces secret and takes ~15&nbsp;min the first time.</p>
    ${tierRow("1&nbsp;&middot;&nbsp;Deploy", "<code>make kind-deploy-openai</code>: cluster + Calico + images + helm chart, models on OpenAI.", "construct: kind deploy (OpenAI)")}
    ${tierRow("2&nbsp;&middot;&nbsp;K8s tests", "Isolation probes (default-deny really denies) and the reference replays, as pods.", "construct: k8s tests")}
    ${tierRow("3&nbsp;&middot;&nbsp;Eval", "The dynamic eval corpus through the in-cluster worker. Detached: follow it with the buttons below.", "construct: kind eval (dynamic)")}
    <div class="row">
      <div class="text">Eval results, once the run has written them</div>
      <button class="secondary" data-cmd="openEvalLog">Latest log</button>
      <button class="secondary" data-cmd="openEvalReport">Latest report</button>
    </div>
    <div class="row">
      <div class="text">Cluster dashboard: findings per scan, stage by stage (starts the port-forward, then opens the page)</div>
      <button data-cmd="kindDashboard">Open dashboard</button>
    </div>
  </div>

  <div class="card">
    <h2>Dev-mode dashboard</h2>
    <div class="row">
      <div class="text">If you run <code>prsec-dashboard</code> on the host (path&nbsp;2 of the README), it serves on :8081</div>
      <button class="secondary" data-cmd="openPort" data-arg="8081">Open :8081</button>
    </div>
  </div>

<script nonce="${nonce}">
  const vscodeApi = acquireVsCodeApi();
  document.body.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-cmd]");
    if (!b) return;
    const arg = b.dataset.arg;
    vscodeApi.postMessage({ cmd: b.dataset.cmd, arg: /^[0-9]+$/.test(arg || "") ? Number(arg) : arg });
  });
  window.addEventListener("message", (e) => {
    const v = e.data.verdict;
    const el = document.getElementById("verdict");
    el.textContent = v || "not run";
    el.className = "badge " + (v || "UNKNOWN");
  });
  vscodeApi.postMessage({ cmd: "refresh" });
</script>
</body>
</html>`;
}

function show(context) {
  if (panel) {
    panel.reveal();
    return;
  }
  panel = vscode.window.createWebviewPanel(
    "constructTestConsole",
    "Construct Test Console",
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );
  panel.webview.html = html(panel.webview);
  panel.webview.onDidReceiveMessage(onMessage, undefined, context.subscriptions);
  panel.onDidDispose(() => (panel = undefined), undefined, context.subscriptions);
}

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand("construct.openTestConsole", () => show(context))
  );
  // In a Codespace on this repo, the console is the landing page.
  const r = root();
  if (process.env.CODESPACES === "true" && r && fs.existsSync(path.join(r, "prsec"))) {
    show(context);
  }
}

function deactivate() {}

module.exports = { activate, deactivate };
