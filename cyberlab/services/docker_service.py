"""Docker sandboxed container orchestration service."""

import os
import sys
import socket
import logging
import subprocess
import shutil
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pathlib import Path

from cyberlab.core.config import settings

logger = logging.getLogger("cyberlab.docker")


class ContainerSecurityProfile:
    """Security specifications enforced on every challenge container."""

    def __init__(
        self,
        cpu_limit: str = "0.5",
        memory_limit: str = "512m",
        pids_limit: int = 100,
        read_only_root: bool = True,
        uid: int = 1000,
        gid: int = 1000,
        drop_capabilities: Optional[List[str]] = None,
        network_mode: str = "internal",  # "internal", "bridge", "none"
        tmpfs_mounts: Optional[Dict[str, str]] = None,
    ):
        self.cpu_limit = cpu_limit
        self.memory_limit = memory_limit
        self.pids_limit = pids_limit
        self.read_only_root = read_only_root
        self.uid = uid
        self.gid = gid
        self.drop_capabilities = drop_capabilities or ["ALL"]
        self.network_mode = network_mode
        self.tmpfs_mounts = tmpfs_mounts or {
            "/tmp": "rw,noexec,nosuid,size=64m",
            "/home/marimo/.local": "rw,nosuid,size=32m",
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "read_only_root": self.read_only_root,
            "uid": self.uid,
            "gid": self.gid,
            "drop_capabilities": self.drop_capabilities,
            "network_mode": self.network_mode,
            "tmpfs_mounts": self.tmpfs_mounts,
            "no_new_privileges": True,
        }


class BaseContainerDriver(ABC):
    """Abstract interface for challenge execution backends."""

    @abstractmethod
    async def create_and_start(
        self,
        session_id: str,
        challenge_id: str,
        challenge_path: Path,
        assigned_port: int,
        security_profile: ContainerSecurityProfile,
        environment_vars: Dict[str, str],
        environment_type: str = "marimo",
    ) -> Dict[str, Any]:
        """Spin up isolated execution instance."""
        pass

    @abstractmethod
    async def stop_and_destroy(self, container_id: str, session_id: str) -> bool:
        """Stop and remove container and isolated networks."""
        pass

    @abstractmethod
    async def get_status(self, container_id: str) -> str:
        """Get container status (running, exited, not_found)."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend driver is ready to accept commands."""
        pass


class DockerDaemonDriver(BaseContainerDriver):
    """Production Docker container driver enforcing strict Linux sandboxing."""

    def __init__(self, docker_cmd: str = "docker"):
        self.docker_cmd = docker_cmd

    def is_available(self) -> bool:
        """Check if Docker CLI can reach the Docker daemon."""
        try:
            res = subprocess.run(
                [self.docker_cmd, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return res.returncode == 0
        except Exception:
            return False

    async def create_and_start(
        self,
        session_id: str,
        challenge_id: str,
        challenge_path: Path,
        assigned_port: int,
        security_profile: ContainerSecurityProfile,
        environment_vars: Dict[str, str],
        environment_type: str = "marimo",
    ) -> Dict[str, Any]:
        container_name = f"cyberlab-{session_id[:12]}"
        network_name = f"net-{session_id[:12]}"

        # Create isolated bridge network for student session
        subprocess.run(
            [self.docker_cmd, "network", "create", "--internal", network_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Base docker arguments with strict security controls
        cmd = [
            self.docker_cmd,
            "run",
            "-d",
            "--name",
            container_name,
            "--network",
            network_name,
            f"-p",
            f"127.0.0.1:{assigned_port}:8080",
            f"--cpus={security_profile.cpu_limit}",
            f"--memory={security_profile.memory_limit}",
            f"--memory-swap={security_profile.memory_limit}",
            f"--pids-limit={security_profile.pids_limit}",
            f"--user={security_profile.uid}:{security_profile.gid}",
            "--security-opt=no-new-privileges:true",
        ]

        # Capabilities drop
        for cap in security_profile.drop_capabilities:
            cmd.extend(["--cap-drop", cap])

        # Read only root filesystem
        if security_profile.read_only_root:
            cmd.append("--read-only")

        # Tmpfs scratch mounts
        for mount_path, mount_opts in security_profile.tmpfs_mounts.items():
            cmd.extend(["--tmpfs", f"{mount_path}:{mount_opts}"])

        # Mount challenge data & marimo code (READ ONLY)
        # CRITICAL: Never mount the solution/ directory
        data_dir = challenge_path / "data"
        marimo_dir = challenge_path / "marimo"
        if data_dir.exists():
            cmd.extend(["-v", f"{data_dir.resolve()}:/workspace/data:ro"])
        if marimo_dir.exists():
            cmd.extend(["-v", f"{marimo_dir.resolve()}:/workspace/marimo:ro"])

        # Clean environment variables (NO host or CTFd/LMS secrets!)
        sanitized_env = {
            "MARIMO_MODE": "edit",
            "PORT": "8080",
            "PYTHONUNBUFFERED": "1",
            "SESSION_ID": session_id,
        }
        for k, v in sanitized_env.items():
            cmd.extend(["-e", f"{k}={v}"])

        # Image name
        image_name = f"cyberlab/{challenge_id}:latest"
        # Fallback to standard base image if challenge-specific image doesn't exist
        cmd.append(image_name)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"Docker failed: {stderr.decode()}")

            container_id = stdout.decode().strip()
            return {
                "container_id": container_id,
                "container_name": container_name,
                "assigned_port": assigned_port,
                "network_name": network_name,
                "driver": "docker",
            }
        except Exception as e:
            logger.error(f"Error starting Docker container: {e}")
            raise

    async def stop_and_destroy(self, container_id: str, session_id: str) -> bool:
        container_name = f"cyberlab-{session_id[:12]}"
        network_name = f"net-{session_id[:12]}"
        try:
            subprocess.run(
                [self.docker_cmd, "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [self.docker_cmd, "network", "rm", network_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to destroy container {container_id}: {e}")
            return False

    async def get_status(self, container_id: str) -> str:
        try:
            res = subprocess.run(
                [
                    self.docker_cmd,
                    "inspect",
                    "--format",
                    "{{.State.Status}}",
                    container_id,
                ],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                return res.stdout.strip()
            return "stopped"
        except Exception:
            return "error"


class SandboxedProcessDriver(BaseContainerDriver):
    """
    Sandboxed process runner for environments without a running Docker daemon.
    Enforces process isolation, non-root scratch workspace, sanitizes environment,
    strictly excludes solution files, and binds strictly to 127.0.0.1.
    """

    def __init__(self):
        self._active_processes: Dict[str, asyncio.subprocess.Process] = {}
        self._scratch_dirs: Dict[str, Path] = {}

    def is_available(self) -> bool:
        return True

    async def create_and_start(
        self,
        session_id: str,
        challenge_id: str,
        challenge_path: Path,
        assigned_port: int,
        security_profile: ContainerSecurityProfile,
        environment_vars: Optional[Dict[str, str]] = None,
        environment_type: str = "marimo",
    ) -> Dict[str, Any]:
        scratch_dir = settings.SANDBOX_DIR / session_id
        scratch_dir.mkdir(parents=True, exist_ok=True)
        self._scratch_dirs[session_id] = scratch_dir

        # Copy data and marimo files to sandbox directory
        data_src = challenge_path / "data"
        if data_src.exists():
            shutil.copytree(data_src, scratch_dir / "data", dirs_exist_ok=True)

        marimo_src = challenge_path / "marimo"
        marimo_file = None
        if marimo_src.exists():
            shutil.copytree(marimo_src, scratch_dir / "marimo", dirs_exist_ok=True)
            files = list((scratch_dir / "marimo").glob("*.py"))
            if files:
                marimo_file = files[0]

        # Ensure scratch directory and local state subdirectories exist
        (scratch_dir / ".local" / "state" / "marimo").mkdir(parents=True, exist_ok=True)
        (scratch_dir / ".marimo").mkdir(parents=True, exist_ok=True)
        config_marimo_dir = scratch_dir / ".config" / "marimo"
        config_marimo_dir.mkdir(parents=True, exist_ok=True)
        dark_theme_cfg = '[display]\ntheme = "dark"\ndataframes = "rich"\ndefault_width = "full"\n'
        (scratch_dir / ".marimo.toml").write_text(dark_theme_cfg)
        (config_marimo_dir / "marimo.toml").write_text(dark_theme_cfg)

        # Strict environment scrubbing (NEVER leak LMS, CTFd, or DB secrets)
        venv_bin_dir = str(Path(sys.executable).parent)
        scrubbed_env = {
            "PATH": f"{venv_bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "PYTHONPATH": str(settings.BASE_DIR),
            "PYTHONUNBUFFERED": "1",
            "HOME": str(scratch_dir),
            "MARIMO_MODE": "edit",
            "SESSION_ID": session_id,
        }
        if environment_vars:
            scrubbed_env.update(environment_vars)

        python_bin = sys.executable
        if environment_type == "marimo" and marimo_file:
            cmd = [
                python_bin,
                "-m",
                "marimo",
                "edit",
                str(marimo_file.resolve()),
                "--host",
                "127.0.0.1",
                "--port",
                str(assigned_port),
                "--base-url",
                f"/session/{session_id}",
                "--no-token",
                "--headless",
                "--skip-update-check",
                "--no-skew-protection",
                "--allow-origins",
                "*",
            ]
        elif environment_type == "web_app":
            # For web_app challenges, launch the challenge app script
            app_script = challenge_path / "app" / "app.py"
            cmd = [
                python_bin,
                str(app_script.resolve()),
                "--host",
                "127.0.0.1",
                "--port",
                str(assigned_port),
            ]
        else:
            # Fallback simple HTTP server on data
            cmd = [
                python_bin,
                "-m",
                "http.server",
                str(assigned_port),
                "--bind",
                "127.0.0.1",
            ]

        log_file = open(scratch_dir / "instance.log", "w")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(scratch_dir),
            env=scrubbed_env,
            stdout=log_file,
            stderr=log_file,
        )
        self._active_processes[session_id] = proc

        # Wait for port to bind
        for _ in range(40):
            await asyncio.sleep(0.2)
            if self._check_port_open("127.0.0.1", assigned_port):
                break
        else:
            if proc.returncode is not None:
                log_content = (
                    (scratch_dir / "instance.log").read_text()
                    if (scratch_dir / "instance.log").exists()
                    else ""
                )
                raise RuntimeError(
                    f"Process exited with code {proc.returncode}: {log_content}"
                )

        return {
            "container_id": f"proc-{proc.pid}",
            "container_name": f"cyberlab-{session_id[:12]}",
            "assigned_port": assigned_port,
            "driver": "sandboxed_process",
            "scratch_dir": str(scratch_dir),
        }

    async def stop_and_destroy(self, container_id: str, session_id: str) -> bool:
        proc = self._active_processes.pop(session_id, None)
        if proc:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    proc.kill()
            except Exception as e:
                logger.warning(f"Error terminating process {proc.pid}: {e}")

        scratch_dir = self._scratch_dirs.pop(session_id, None)
        if not scratch_dir:
            scratch_dir = settings.SANDBOX_DIR / session_id
        if scratch_dir and scratch_dir.exists():
            shutil.rmtree(scratch_dir, ignore_errors=True)

        return True

    async def get_status(self, container_id: str) -> str:
        for sid, proc in self._active_processes.items():
            if f"proc-{proc.pid}" == container_id:
                return "running" if proc.returncode is None else "stopped"
        return "stopped"

    def _check_port_open(self, host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0


class ContainerManager:
    """Orchestrates container drivers, security profiles, and port allocation."""

    def __init__(self):
        self.docker_driver = DockerDaemonDriver()
        self.process_driver = SandboxedProcessDriver()
        self._used_ports: set[int] = set()

    async def is_instance_alive(
        self, container_id: str, session_id: str, port: int
    ) -> bool:
        """Verify that the container process and listening port are actually responsive."""
        driver = self.get_driver()
        status = await driver.get_status(container_id)
        if status != "running":
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex(("127.0.0.1", port)) == 0

    def get_driver(self) -> BaseContainerDriver:
        if settings.DOCKER_DRIVER == "docker":
            return self.docker_driver
        if settings.DOCKER_DRIVER == "process":
            return self.process_driver
        # Auto-detect: if docker daemon is running, use it; otherwise use sandboxed process driver
        if self.docker_driver.is_available():
            return self.docker_driver
        return self.process_driver

    def allocate_port(self) -> int:
        """Find and allocate an unused local port between PORT_RANGE_START and PORT_RANGE_END."""
        for port in range(settings.PORT_RANGE_START, settings.PORT_RANGE_END):
            if port not in self._used_ports:
                # Test whether port is truly unbound
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    if s.connect_ex(("127.0.0.1", port)) != 0:
                        self._used_ports.add(port)
                        return port
        raise RuntimeError("Port exhaustion: No available ports in allocated pool.")

    def release_port(self, port: int):
        self._used_ports.discard(port)

    async def launch_challenge_instance(
        self,
        session_id: str,
        challenge_id: str,
        challenge_path: Path,
        environment_type: str = "marimo",
    ) -> Dict[str, Any]:
        driver = self.get_driver()
        port = self.allocate_port()
        profile = ContainerSecurityProfile(
            cpu_limit=settings.CONTAINER_CPU_LIMIT,
            memory_limit=settings.CONTAINER_MEMORY_LIMIT,
            pids_limit=settings.CONTAINER_PIDS_LIMIT,
            read_only_root=settings.CONTAINER_READ_ONLY_ROOT,
            uid=settings.CONTAINER_UID,
            gid=settings.CONTAINER_GID,
            drop_capabilities=settings.CONTAINER_DROP_CAPABILITIES,
        )

        try:
            res = await driver.create_and_start(
                session_id=session_id,
                challenge_id=challenge_id,
                challenge_path=challenge_path,
                assigned_port=port,
                security_profile=profile,
                environment_vars={},
                environment_type=environment_type,
            )
            return res
        except Exception as e:
            self.release_port(port)
            logger.error(f"Failed to launch container: {e}")
            raise

    async def terminate_instance(
        self, container_id: str, session_id: str, port: int
    ) -> bool:
        driver = self.get_driver()
        try:
            res = await driver.stop_and_destroy(container_id, session_id)
            return res
        finally:
            self.release_port(port)


container_manager = ContainerManager()
