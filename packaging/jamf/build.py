#!/usr/bin/env python3
"""Build and inspect one unsigned Jamf installer. Never installs on this host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "packaging/jamf"
MANAGED = Path("Library/Application Support/VGS/ShellFirm")
PAYLOADS = {"binary": MANAGED / "bin/shellfirm", "policy": MANAGED / "policy/.shellfirm.yaml"}


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run(*args, **kwargs):
    return subprocess.check_output([str(arg) for arg in args], text=True, **kwargs).strip()


def versions():
    value = json.loads((CONFIG / "versions.json").read_text())
    for kind in PAYLOADS:
        if not re.fullmatch(r"\d+(?:\.\d+){2,3}", value[kind]):
            raise ValueError(f"Invalid {kind} package version")
    return value


def inspect_package(package, kind, version, expected_sha):
    with tempfile.TemporaryDirectory(prefix="shellfirm-inspect-") as tmp:
        expanded = Path(tmp) / "expanded"
        run("/usr/sbin/pkgutil", "--expand-full", package, expanded)
        info = ET.parse(expanded / "PackageInfo").getroot()
        assert info.get("identifier") == f"io.vgs.shellfirm.{kind}"
        assert info.get("version") == version
        assert info.get("install-location") == "/"
        payload = expanded / "Payload"
        files = [p.relative_to(payload) for p in payload.rglob("*") if not p.is_dir()]
        assert files == [PAYLOADS[kind]], f"Unexpected payload: {files}"
        installed = payload / PAYLOADS[kind]
        assert not installed.is_symlink()
        assert sha256(installed) == expected_sha
        assert installed.stat().st_mode & 0o777 == (0o755 if kind == "binary" else 0o644)
        for script in (expanded / "Scripts").iterdir():
            assert script.name in {"preinstall", "postinstall"}
            assert not re.search(r"@[A-Z_]+@", script.read_text()), "Unrendered installer variable"
            run("/bin/zsh", "-n", script)


def build(kind, binary, output, commit):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("Build on native Apple Silicon macOS")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("A full source commit SHA is required")
    release = versions()
    app = tomllib.loads((ROOT / "shellfirm/Cargo.toml").read_text())["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", app):
        raise ValueError("Unsupported application version")
    binary = binary.resolve(strict=True)
    if run("/usr/bin/lipo", "-archs", binary) != "arm64":
        raise ValueError("Binary must contain only arm64")
    expected_version = f"shellfirm {app}"
    if run(binary, "--version") != expected_version:
        raise ValueError("Binary version differs from Cargo.toml")
    # CLI validation never runs a risky command or modifies the user's shell.
    policy = ROOT / ".shellfirm.yaml"
    print(run(binary, "policy", "validate", policy))
    policy_sha = sha256(policy)
    source = binary if kind == "binary" else policy
    payload_sha = sha256(source)
    output.mkdir(parents=True, exist_ok=True)
    suffix = "-arm64" if kind == "binary" else ""
    name = f"VGS-ShellFirm-{kind.title()}-{release[kind]}{suffix}-unsigned.pkg"
    package = output.resolve() / name
    if package.exists():
        raise FileExistsError(f"Refusing to overwrite {package}")
    with tempfile.TemporaryDirectory(prefix="shellfirm-package-") as tmp:
        staging = Path(tmp) / "root"
        target = staging / PAYLOADS[kind]
        target.parent.mkdir(parents=True)
        shutil.copyfile(source, target)
        target.chmod(0o755 if kind == "binary" else 0o644)
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        replacements = {"@APP_VERSION@": app, "@PACKAGE_VERSION@": release[kind],
                        "@POLICY_SHA256@": policy_sha}
        for template in (CONFIG / "installers" / kind).iterdir():
            rendered = template.read_text()
            for key, value in replacements.items():
                rendered = rendered.replace(key, value)
            destination = scripts / template.name
            destination.write_text(rendered)
            destination.chmod(0o755)
            run("/bin/zsh", "-n", destination)
        print(run("/usr/bin/pkgbuild", "--root", staging, "--scripts", scripts,
                  "--identifier", f"io.vgs.shellfirm.{kind}", "--version", release[kind],
                  "--install-location", "/", "--ownership", "recommended", package,
                  env={**os.environ, "COPYFILE_DISABLE": "1"}))
    inspect_package(package, kind, release[kind], payload_sha)
    manifest = {
        "kind": kind, "file_name": name, "package_version": release[kind],
        "package_identifier": f"io.vgs.shellfirm.{kind}",
        "package_sha256": sha256(package), "payload_sha256": payload_sha,
        "source_commit": commit, "application_version": app,
        "policy_sha256": policy_sha, "unsigned": True,
        "promotion": ({"activation_expected_version": expected_version,
                       "health_check_binary_receipt": release["binary"]} if kind == "binary" else
                      {"activation_expected_policy_sha": policy_sha,
                       "health_check_policy_receipt": release["policy"],
                       "health_check_policy_sha256": policy_sha}),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "SHA256SUMS").write_text(f"{manifest['package_sha256']}  {name}\n")
    print(f"Verified {name}; no software was installed.")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=PAYLOADS)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    build(args.kind, args.binary, args.output, args.commit)
