"""Optional sync/import adapter for an authorized local GitLab instance."""
from __future__ import annotations
import os, urllib.request

def fetch_project_file(base_url: str, project_path: str, file_path: str, token: str | None = None) -> bytes:
    base = base_url.rstrip("/")
    encoded_project = project_path.replace("/","%2F")
    encoded_file = file_path.replace("/","%2F")
    url = f"{base}/api/v4/projects/{encoded_project}/repository/files/{encoded_file}/raw?ref=main"
    request = urllib.request.Request(url)
    if token:
        request.add_header("PRIVATE-TOKEN", token)
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read()

def configured() -> bool:
    return bool(os.environ.get("VANGUARD_GITLAB_URL"))
