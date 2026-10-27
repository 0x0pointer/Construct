"""Workbench launcher: the only service that holds the Docker socket.

The worker asks it, over a private network, to create/destroy a scan network and to run one
workbench. The launcher builds every container itself from a fixed recipe (DockerRunner's
hardened kwargs) and refuses anything outside it: images not named in the AppSec policy, host
paths outside the work/skills/harness roots, foreign networks, other commands. A compromised
worker can therefore only start the workbenches it could start anyway, not a root shell on the host.
"""
