import os
import subprocess
import shutil
import threading
import uuid
import atexit
from typing import List, Tuple, Optional, Dict, Set

# Active processes and containers tracking per scan_id (Sets allow concurrent tools per scan without collision)
_ACTIVE_PROCS: Dict[str, Set[subprocess.Popen]] = {}
_ACTIVE_CONTAINERS: Dict[str, Set[str]] = {}
_CANCELLED_SCANS: Set[str] = set()
_LOCK = threading.Lock()

def _cleanup_all_active_containers():
    """Cleanup all tracked active docker containers on interpreter exit to prevent orphans."""
    with _LOCK:
        for scan_id, containers in list(_ACTIVE_CONTAINERS.items()):
            for container_name in list(containers):
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", container_name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    )
                except Exception:
                    pass

atexit.register(_cleanup_all_active_containers)

class ScanCancelledException(Exception):
    """Raised when a scan has been cancelled by the user."""
    pass

def mark_scan_cancelled(scan_id: str) -> None:
    """Marks a scan session as cancelled and terminates any active subprocesses or containers for that scan."""
    with _LOCK:
        _CANCELLED_SCANS.add(scan_id)
        
        # Terminate all active subprocesses belonging to this scan
        procs = list(_ACTIVE_PROCS.get(scan_id, set()))
        for proc in procs:
            try:
                proc.kill()
            except Exception:
                pass
                
        # Remove and stop all active docker containers belonging to this scan
        containers = list(_ACTIVE_CONTAINERS.get(scan_id, set()))
        for container_name in containers:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
            except Exception:
                pass

def is_scan_cancelled(scan_id: str) -> bool:
    """Checks if a scan has been flagged as cancelled."""
    with _LOCK:
        return scan_id in _CANCELLED_SCANS

def clear_scan_cancelled(scan_id: str) -> None:
    """Cleans up cancellation flags and process records for a scan session."""
    with _LOCK:
        _CANCELLED_SCANS.discard(scan_id)
        _ACTIVE_PROCS.pop(scan_id, None)
        _ACTIVE_CONTAINERS.pop(scan_id, None)

import time

# Automatically ensure local tools/ directory is in PATH for direct high-speed execution
_TOOLS_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools"))
if os.path.exists(_TOOLS_DIR) and _TOOLS_DIR not in os.environ.get("PATH", ""):
    os.environ["PATH"] = f"{_TOOLS_DIR}{os.pathsep}{os.environ.get('PATH', '')}"

def get_docker_volume_path(local_path: str) -> str:
    """Converts a local Windows path to a format compatible with Docker -v flag."""
    abs_path = os.path.abspath(local_path).replace("\\", "/")
    return abs_path

_DOCKER_AVAILABLE_CACHE: Optional[bool] = None
_DOCKER_CACHE_TIME: float = 0.0

def is_docker_available() -> bool:
    """
    Checks if Docker daemon is running AND actually capable of executing containers.
    Guards against environments where Docker daemon is active but 'docker run' hangs.
    Caches result for 60 seconds to prevent delay.
    """
    global _DOCKER_AVAILABLE_CACHE, _DOCKER_CACHE_TIME
    
    forced_setting = os.getenv("YEMENSCAN_USE_DOCKER", "").strip().lower()
    if forced_setting in ("0", "false", "no", "off"):
        return False
    if forced_setting in ("1", "true", "yes", "on"):
        return True

    now = time.time()
    if _DOCKER_AVAILABLE_CACHE is not None and (now - _DOCKER_CACHE_TIME) < 120:
        return _DOCKER_AVAILABLE_CACHE

    try:
        # Step 1: Quick Docker daemon ping
        res = subprocess.run(
            ["docker", "info"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0
        )
        if res.returncode != 0:
            _DOCKER_AVAILABLE_CACHE = False
            _DOCKER_CACHE_TIME = now
            return False

        _DOCKER_AVAILABLE_CACHE = True
    except Exception:
        _DOCKER_AVAILABLE_CACHE = False

    _DOCKER_CACHE_TIME = now
    return _DOCKER_AVAILABLE_CACHE

def run_docker_tool(
    image: str,
    args: List[str],
    volume_dir: str,
    timeout: int = 45,
    container_mount: str = "/data",
    extra_volumes: Optional[List[Tuple[str, str]]] = None,
    scan_id: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Executes a security tool inside a temporary Docker container mounting volume_dir to /data
    and any optional extra_volumes specified as (host_path, container_path).
    Supports scan_id tracking for graceful cancellation and uses globally unique container names.
    """
    if scan_id and is_scan_cancelled(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} has been cancelled by user.")

    # 1. Native/Bundled Tool Execution Check:
    # If the tool binary (subfinder, naabu, httpx, nuclei) is installed in PATH,
    # run it directly for maximum performance and avoid container overhead.
    tool_binary = image.split("/")[-1].split(":")[0]
    local_bin = shutil.which(tool_binary) or shutil.which(f"{tool_binary}.exe")
    prefer_local = os.getenv("PREFER_LOCAL_TOOLS", "true").lower() in ("true", "1", "yes")

    if local_bin and (prefer_local or not is_docker_available()):
        local_args = []
        for arg in args:
            translated = arg.replace(container_mount, volume_dir)
            if extra_volumes:
                for host_p, cont_p in extra_volumes:
                    translated = translated.replace(cont_p, host_p)
            local_args.append(translated)
        return run_local_tool([local_bin] + local_args, cwd=volume_dir, timeout=timeout, scan_id=scan_id)

    # If Docker cannot actually run containers on this system, exit immediately with false
    if not is_docker_available():
        return False, "Docker is not available or unable to run containers on this host system."

    vol_path = get_docker_volume_path(volume_dir)
    cmd = ["docker", "run", "--rm"]
    
    # Generate a unique container name with random hex suffix to prevent Docker name collisions
    container_suffix = uuid.uuid4().hex[:6]
    clean_name = "".join(c if c.isalnum() or c in "_-" else "_" for c in scan_id) if scan_id else "tool"
    container_name = f"ys_{clean_name}_{container_suffix}"
    cmd.extend(["--name", container_name])
        
    cmd.extend(["-v", f"{vol_path}:{container_mount}"])
    if extra_volumes:
        for host_p, cont_p in extra_volumes:
            cmd.extend(["-v", f"{get_docker_volume_path(host_p)}:{cont_p}"])
    cmd.append(image)
    cmd.extend(args)
    
    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        if scan_id:
            with _LOCK:
                _ACTIVE_PROCS.setdefault(scan_id, set()).add(proc)
                _ACTIVE_CONTAINERS.setdefault(scan_id, set()).add(container_name)

        stdout, stderr = proc.communicate(timeout=timeout)

        if scan_id and is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled by user.")

        if proc.returncode == 0:
            return True, stdout
        else:
            return False, f"Process returned code {proc.returncode}: {stderr}"
    except subprocess.TimeoutExpired as te:
        if proc:
            proc.kill()
        try:
            subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass
        partial_stdout = te.output or ""
        if isinstance(partial_stdout, bytes):
            partial_stdout = partial_stdout.decode("utf-8", errors="replace")
        if partial_stdout and len(partial_stdout.strip()) > 0:
            return True, partial_stdout
        return False, f"Tool execution timed out after {timeout} seconds"
    except ScanCancelledException:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass
        raise
    except Exception as e:
        return False, f"Exception while running {image}: {str(e)}"
    finally:
        if scan_id and proc:
            with _LOCK:
                if scan_id in _ACTIVE_PROCS:
                    _ACTIVE_PROCS[scan_id].discard(proc)
                if scan_id in _ACTIVE_CONTAINERS:
                    _ACTIVE_CONTAINERS[scan_id].discard(container_name)

def run_local_tool(
    cmd: List[str],
    cwd: str,
    timeout: int = 60,
    scan_id: Optional[str] = None
) -> Tuple[bool, str]:
    """Executes a local command line tool with working directory, timeout, and scan cancellation support."""
    if scan_id and is_scan_cancelled(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} has been cancelled by user.")

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            encoding="utf-8",
            errors="replace"
        )
        if scan_id:
            with _LOCK:
                _ACTIVE_PROCS.setdefault(scan_id, set()).add(proc)

        stdout, stderr = proc.communicate(timeout=timeout)

        if scan_id and is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled by user.")

        if proc.returncode == 0:
            return True, stdout
        else:
            return False, f"Process returned code {proc.returncode}: {stderr}"
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
        return False, f"Execution timed out after {timeout} seconds"
    except ScanCancelledException:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        raise
    except Exception as e:
        return False, f"Exception executing local tool: {str(e)}"
    finally:
        if scan_id and proc:
            with _LOCK:
                if scan_id in _ACTIVE_PROCS:
                    _ACTIVE_PROCS[scan_id].discard(proc)
