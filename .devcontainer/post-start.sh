#!/usr/bin/env bash
# kind + Calico need more inotify headroom than the Codespaces defaults; these do not
# persist across container restarts, so they are set on every start. Harmless elsewhere.
sudo sysctl -w fs.inotify.max_user_watches=1048576 fs.inotify.max_user_instances=1024 >/dev/null 2>&1 || true
