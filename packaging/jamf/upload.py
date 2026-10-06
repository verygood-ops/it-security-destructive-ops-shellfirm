#!/usr/bin/env python3
"""Create a versioned Jamf package and upload it. Never edits a deployment policy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward credentials to another destination.


class Jamf:
    def __init__(self, url, client_id, client_secret):
        parts = urllib.parse.urlsplit(url)
        if (parts.scheme != "https" or not parts.hostname or parts.username
                or parts.password or parts.query or parts.fragment or parts.path not in ("", "/")):
            raise ValueError("JAMF_URL must be an HTTPS origin without credentials or a path")
        self.url = url.rstrip("/")
        self.token = None
        self.opener = urllib.request.build_opener(NoRedirect())
        form = urllib.parse.urlencode({"grant_type": "client_credentials",
                                       "client_id": client_id, "client_secret": client_secret}).encode()
        response = self.request("POST", "/api/v1/oauth/token", form,
                                "application/x-www-form-urlencoded")
        self.token = response["access_token"]
        if os.environ.get("GITHUB_ACTIONS") == "true":
            escaped = self.token.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::add-mask::{escaped}", flush=True)

    def request(self, method, path, data=None, content_type="application/json"):
        headers = {"Accept": "application/json", "Content-Type": content_type}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=120) as response:
                body = response.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            # Response bodies can contain credentials or internal details. Do not print them.
            raise RuntimeError(f"Jamf {method} {path.split('?')[0]} returned HTTP {exc.code}") from None
        except urllib.error.URLError:
            raise RuntimeError("Jamf connection failed; check URL, TLS and network access") from None


def load_artifact(directory, expected_commit):
    manifest = json.loads((directory / "manifest.json").read_text())
    kind = manifest["kind"]
    version = manifest["package_version"]
    if kind not in ("binary", "policy") or not re.fullmatch(r"\d+(?:\.\d+){2,3}", version):
        raise ValueError("Invalid artifact kind or version")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit) or manifest["source_commit"] != expected_commit:
        raise ValueError("Artifact does not belong to this workflow commit")
    suffix = "-arm64" if kind == "binary" else ""
    expected_name = f"VGS-ShellFirm-{kind.title()}-{version}{suffix}-unsigned.pkg"
    if manifest["file_name"] != expected_name:
        raise ValueError("Unexpected package filename")
    package = directory / expected_name
    if package.is_symlink() or not package.is_file():
        raise ValueError("Package must be a regular file")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    if digest != manifest["package_sha256"]:
        raise ValueError("Package checksum mismatch; upload stopped")
    return manifest, package


def package_metadata(manifest, category_id):
    if not re.fullmatch(r"-1|\d+", category_id):
        raise ValueError("JAMF_CATEGORY_ID must be a numeric category ID, or -1 for None")
    kind = manifest["kind"]
    return {
        "packageName": f"VGS ShellFirm {kind.title()} {manifest['package_version']}" +
                       (" (Apple Silicon)" if kind == "binary" else ""),
        "fileName": manifest["file_name"], "categoryId": category_id,
        "priority": 10 if kind == "binary" else 20,
        "info": "VGS ShellFirm unsigned pilot installer. Manual deployment promotion required.",
        "notes": f"Source commit: {manifest['source_commit']}; "
                 f"Package SHA-256: {manifest['package_sha256']}; "
                 f"Policy SHA-256: {manifest['policy_sha256']}. "
                 "Update activation/health-check pins when promoting. Standard computer policy only.",
        "fillUserTemplate": False, "fillExistingUsers": False, "rebootRequired": False,
        "osInstall": False, "suppressUpdates": False, "suppressFromDock": False,
        "suppressEula": False, "suppressRegistration": False,
    }


def verified(record, manifest):
    return (record.get("fileName") == manifest["file_name"]
            and record.get("cloudTransferStatus") == "READY"
            and record.get("sha256", "").lower() == manifest["package_sha256"])


def upload(jamf, manifest, package, category_id="-1", wait=time.sleep):
    metadata = package_metadata(manifest, category_id)
    query = urllib.parse.urlencode({"filter": f'fileName=="{manifest["file_name"]}"', "page-size": 100})
    existing = jamf.request("GET", "/api/v1/packages?" + query)
    if existing["totalCount"]:
        if existing["totalCount"] == 1:
            record = existing["results"][0]
            if verified(record, manifest):
                return str(record["id"]), "already present; checksum verified"
        raise RuntimeError("This filename already exists in Jamf with a different checksum or incomplete upload. "
                           "Review that record manually or bump the package version. Nothing was overwritten.")
    created = jamf.request("POST", "/api/v1/packages", metadata)
    package_id = str(created["id"])
    if not re.fullmatch(r"\d+", package_id):
        raise ValueError("Jamf returned an invalid package ID")
    print(f"Created Jamf package record {package_id}. If upload fails, review this record before retrying.")
    boundary = "shellfirm-" + secrets.token_hex(24)
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{package.name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
    body += package.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    jamf.request("POST", f"/api/v1/packages/{package_id}/upload", body,
                 f"multipart/form-data; boundary={boundary}")
    # Do not pre-fill the server hash: compare the server-computed checksum after upload.
    for attempt in range(24):
        record = jamf.request("GET", f"/api/v1/packages/{package_id}")
        if verified(record, manifest):
            return package_id, "uploaded; READY and server checksum verified"
        if record.get("cloudTransferStatus") == "READY" and record.get("sha256"):
            raise RuntimeError(f"Jamf package {package_id} checksum or filename mismatch; do not deploy")
        if attempt < 23:
            wait(5)
    raise RuntimeError(f"Jamf package {package_id} did not become READY with the expected checksum; do not deploy")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    manifest, package = load_artifact(args.directory, args.commit)
    required = ("JAMF_URL", "JAMF_CLIENT_ID", "JAMF_CLIENT_SECRET")
    if any(not os.environ.get(key) for key in required):
        raise ValueError("Configure JAMF_URL, JAMF_CLIENT_ID and JAMF_CLIENT_SECRET in the jamf environment")
    jamf = Jamf(*(os.environ[key] for key in required))
    try:
        package_id, status = upload(jamf, manifest, package, os.environ.get("JAMF_CATEGORY_ID") or "-1")
        message = f"Jamf package {package_id}: {status}. No deployment policy was changed."
        print(message)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                summary.write(message + "\n")
    finally:
        try:
            jamf.request("POST", "/api/v1/auth/invalidate-token")
        except RuntimeError:
            print("Token invalidation unavailable; the short-lived token will expire.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        print(f"Upload stopped: {exc}", file=sys.stderr)
        sys.exit(1)
