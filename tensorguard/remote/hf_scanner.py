import io
import requests
from typing import List, Dict, Any, Optional
from tensorguard.rules import Vulnerability
from tensorguard.scanners.ast_scanner import scan_python_code
from tensorguard.scanners.pickle_scanner import PickleScanner

HF_API_BASE = "https://huggingface.co/api/models"
HF_RESOLVE_BASE = "https://huggingface.co"


class RemoteHFScanner:
    def __init__(self, repo_id: str, revision: str = "main", auth_token: Optional[str] = None):
        self.repo_id = repo_id
        self.revision = revision
        self.headers = {"User-Agent": "TensorGuard-RemoteScanner/0.1"}
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

    def list_repo_files(self) -> List[Dict[str, Any]]:
        """Fetch repository file tree via Hugging Face Hub API."""
        url = f"{HF_API_BASE}/{self.repo_id}/tree/{self.revision}"
        resp = requests.get(url, headers=self.headers, timeout=15)
        if resp.status_code == 404:
            raise FileNotFoundError(f"Hugging Face repository '{self.repo_id}' not found.")
        elif resp.status_code != 200:
            raise RuntimeError(f"Hugging Face API returned HTTP {resp.status_code}: {resp.text}")
        return resp.json()

    def fetch_byte_range(self, rpath: str, start: int = 0, length: int = 16384) -> bytes:
        """Fetch byte slice using the resolve endpoint with HTTP Range headers."""
        url = f"{HF_RESOLVE_BASE}/{self.repo_id}/resolve/{self.revision}/{rpath}"
        range_headers = {**self.headers, "Range": f"bytes={start}-{start + length - 1}"}
        resp = requests.get(url, headers=range_headers, allow_redirects=True, timeout=20)
        if resp.status_code in (200, 206):
            return resp.content
        return b""

    def fetch_full_text(self, rpath: str) -> str:
        """Fetch remote text file contents directly into memory."""
        url = f"{HF_RESOLVE_BASE}/{self.repo_id}/resolve/{self.revision}/{rpath}"
        resp = requests.get(url, headers=self.headers, allow_redirects=True, timeout=20)
        resp.raise_for_status()
        return resp.text

    def scan_remote_repo(self) -> List[Vulnerability]:
        """Scan the remote repository without downloading full model weights."""
        findings: List[Vulnerability] = []
        files = self.list_repo_files()

        for item in files:
            rpath = item.get("path", "")
            target_display = f"hf://{self.repo_id}/{rpath}"

            # 1. Inspect Python source files (custom modeling logic)
            if rpath.endswith(".py"):
                try:
                    content = self.fetch_full_text(rpath)
                    findings.extend(scan_python_code(content, target_display))
                except Exception as e:
                    findings.append(
                        Vulnerability(
                            file_path=target_display,
                            severity="LOW",
                            rule_id="TG-008-REMOTE-FETCH-FAIL",
                            message=f"Failed to fetch remote script: {str(e)}",
                            evidence="",
                        )
                    )

            # 2. Pickled weights (.bin, .pt, .pkl)
            elif any(rpath.endswith(ext) for ext in (".bin", ".pt", ".pkl")):
                try:
                    raw_chunk = self.fetch_byte_range(rpath, start=0, length=16384)

                    # Check for Git LFS pointer text file
                    if raw_chunk.startswith(b"version https://git-lfs"):
                        continue

                    scanner = PickleScanner()
                    findings.extend(scanner.scan_bytes(raw_chunk, target_display, is_partial=True))
                except Exception as e:
                    findings.append(
                        Vulnerability(
                            file_path=target_display,
                            severity="LOW",
                            rule_id="TG-008-REMOTE-FETCH-FAIL",
                            message=f"Failed to inspect remote stream: {str(e)}",
                            evidence="",
                        )
                    )

        return findings