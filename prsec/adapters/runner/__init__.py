from prsec.adapters.protocols import Runner


def get_runner(name: str | None = None) -> Runner:
    if name is None:
        from prsec.config import settings

        name = settings().runner
    if name == "docker":
        from prsec.adapters.runner.docker import DockerRunner

        return DockerRunner()
    if name == "launcher":
        from prsec.adapters.runner.launcher import LauncherRunner

        return LauncherRunner()
    if name == "local":
        from prsec.adapters.runner.local import LocalRunner

        return LocalRunner()
    raise ValueError(f"unknown runner {name!r}; known: docker, launcher, local")
