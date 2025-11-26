"""Build the hotkey_manager wheel inside an isolated virtual environment."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        sys.stderr.write("hotkey_manager builds are supported on Linux only.\n")
        sys.exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-dir", required=True)
    parser.add_argument("--wheel-dir", required=True)
    parser.add_argument("--venv-dir", required=True)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    package_dir = Path(args.package_dir)
    wheel_dir = Path(args.wheel_dir)
    venv_dir = Path(args.venv_dir)
    package_dir.mkdir(parents=True, exist_ok=True)
    wheel_dir.mkdir(parents=True, exist_ok=True)
    base_python = Path(args.python)
    if not venv_dir.exists():
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(base_python), "-m", "venv", str(venv_dir)], check=True)
    venv_python = venv_dir / "bin" / "python"
    venv_pip = venv_dir / "bin" / "pip"
    env = os.environ.copy()
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    env.setdefault("PIP_ROOT_USER_ACTION", "ignore")
    subprocess.run(
        [str(venv_pip), "install", "--upgrade", "pip", "build"], check=True, env=env
    )
    subprocess.run(
        [str(venv_python), "-m", "build", "--wheel", "--outdir", str(wheel_dir), str(package_dir)],
        check=True,
        env=env,
    )
