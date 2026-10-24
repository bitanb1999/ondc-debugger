"""
Download ONDC's official retail API specs into ./specs, for the debugger to validate against.

    python -m debugger.fetch_spec                      # default: retail 1.2.0 and 2.0.2
    python -m debugger.fetch_spec draft-b2c-1.2.5      # any branch of the spec repo

The specs live in ONDC's GitHub repository and aren't redistributed with this
tool. Only the one file needed (api/build/build.yaml) is downloaded from each
branch, using git's sparse checkout, so this takes seconds, not the full repo.
Requires git.
"""

import os
import shutil
import subprocess
import sys
import tempfile

import yaml

REPO = "https://github.com/ONDC-Official/ONDC-RET-Specifications"
DEFAULT_BRANCHES = ["draft-1.x", "release-2.0.2"]  # retail 1.2.0 and 2.0.2
OUT_DIR = os.environ.get("ONDC_SPEC_DIR", "specs")


def fetch(branch: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        def git(*args, cwd=tmp):
            subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)

        git("clone", "--quiet", "--filter=blob:none", "--no-checkout", "--depth", "1",
            "--branch", branch, REPO, "repo")
        repo = os.path.join(tmp, "repo")
        git("sparse-checkout", "set", "--no-cone", "api/build/build.yaml", cwd=repo)
        git("checkout", "--quiet", cwd=repo)

        src = os.path.join(repo, "api", "build", "build.yaml")
        with open(src) as f:
            version = yaml.safe_load(f).get("info", {}).get("version", branch)
        os.makedirs(OUT_DIR, exist_ok=True)
        dest = os.path.join(OUT_DIR, f"retail-{version}.yaml")
        shutil.copyfile(src, dest)
        return dest


if __name__ == "__main__":
    for branch in sys.argv[1:] or DEFAULT_BRANCHES:
        try:
            print(f"{branch}: saved {fetch(branch)}")
        except subprocess.CalledProcessError as exc:
            print(f"{branch}: failed: {exc.stderr.decode().strip()}", file=sys.stderr)
