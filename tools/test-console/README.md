# Construct Test Console (VS Code extension)

The page a Codespace opens on attach: every test tier with a short explanation, a
**▶ Run** button, and buttons that open the matching output — the startup-test verdict
and log, the latest kind eval report, the dashboards.

The extension holds no test logic. Each button runs the matching task from
`.vscode/tasks.json` (all plain `make` targets), so the panel always agrees with the
terminal and with CI. Command palette: **Construct: Open Test Console**. It opens by
itself only in a Codespace (`CODESPACES=true`) on this repository.

The Codespace installs it on attach (`.devcontainer/post-attach.sh`).

## Rebuilding the .vsix

```bash
cd tools/test-console
npx --yes @vscode/vsce@3.9.2 package --no-dependencies -o construct-test-console.vsix
```

## Trying it locally

Open this folder in VS Code and press <kbd>F5</kbd> (Run Extension), then open the
repository root in the window that appears and run **Construct: Open Test Console**.
