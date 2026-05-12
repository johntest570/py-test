#!/usr/bin/env python3
"""SCM-agnostic client for pull request operations.

Provides an abstract ``SCMClient`` interface with concrete implementations for
GitHub, Bitbucket Cloud, and GitLab.  All HTTP calls use :mod:`urllib.request`
(stdlib) so that **no** third-party packages are required beyond what the MCP
server already ships.

Usage::

    from scm_client import create_scm_client, ChangedFile

    scm = create_scm_client("github", token="ghp_...", base_url="https://api.github.com")
    files = scm.get_pr_changed_files("owner/repo", pr_number=42)
    content = scm.get_file_content("owner/repo", "src/main.py", ref="abc123")
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("pr_scan.scm_client")

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ChangedFile:
    """Represents a file changed in a pull request."""
    filename: str
    status: str          # added | modified | removed | renamed | copied
    sha: str             # blob SHA
    additions: int = 0
    deletions: int = 0
    patch: str = ""      # unified diff (may be empty for binary files)
    previous_filename: Optional[str] = None  # set when status == "renamed"


@dataclass
class PRComment:
    """A comment on a pull request."""
    id: int
    body: str
    user: str = ""


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class SCMClient(ABC):
    """Abstract base for SCM provider clients.

    Every concrete implementation accepts a pre-provisioned access token
    (injected by the CI system from a secret manager) and a base URL so
    that GitHub Enterprise / self-hosted instances work transparently.
    """

    def __init__(self, token: str, base_url: str) -> None:
        self.token = token
        self.base_url = base_url.rstrip("/")

    # -- PR metadata -------------------------------------------------------

    @abstractmethod
    def get_pr_changed_files(self, repo: str, pr_number: int) -> List[ChangedFile]:
        """Return the list of files changed in the given PR."""

    @abstractmethod
    def get_pr_head_sha(self, repo: str, pr_number: int) -> Tuple[str, str]:
        """Return (head_sha, base_branch) for the given PR.

        Fetches live from the SCM API so callers don't have to pass --head-sha
        and --branch manually.
        """

    @abstractmethod
    def get_file_content(self, repo: str, path: str, ref: str) -> bytes:
        """Return the raw bytes of *path* at commit *ref*."""

    # -- Comments -----------------------------------------------------------

    @abstractmethod
    def post_pr_comment(self, repo: str, pr_number: int, body: str) -> int:
        """Post a new comment on the PR.  Returns the comment ID."""

    @abstractmethod
    def update_pr_comment(self, repo: str, comment_id: int, body: str) -> None:
        """Update an existing PR comment in-place."""

    @abstractmethod
    def find_bot_comment(self, repo: str, pr_number: int, marker: str) -> Optional[int]:
        """Return the comment ID whose body contains *marker*, or ``None``."""

    # -- File metadata ------------------------------------------------------

    def get_file_blob_sha(self, repo: str, path: str, ref: str) -> Optional[str]:
        """Return the blob SHA for *path* at *ref*, or ``None`` if not found.

        Used to pre-resolve SHAs from a stable ref (e.g. the source branch)
        before committing to a newly created branch, avoiding race conditions
        with eventual consistency.  Default returns ``None``; providers that
        need it (GitHub) override this.
        """
        return None

    # -- Branches & commits -------------------------------------------------

    @abstractmethod
    def create_branch(self, repo: str, branch_name: str, from_sha: str) -> None:
        """Create a new branch pointing at *from_sha*."""

    @abstractmethod
    def branch_exists(self, repo: str, branch_name: str) -> bool:
        """Return True if branch already exists."""

    @abstractmethod
    def commit_file(
        self,
        repo: str,
        branch: str,
        path: str,
        content: bytes,
        message: str,
        sha: Optional[str] = None,
    ) -> str:
        """Create or update *path* on *branch*.  Returns the new commit SHA."""

    # -- Pull requests ------------------------------------------------------

    @abstractmethod
    def create_pull_request(
        self,
        repo: str,
        title: str,
        head: str,
        base: str,
        body: str,
        *,
        cross_repo_head_owner: Optional[str] = None,
    ) -> int:
        """Open a new PR.  Returns the PR number.

        *cross_repo_head_owner* (GitHub only): when PR is opened against *repo*
        (upstream) but *head* lives on a fork, pass the fork ``owner/login`` —
        POST body sends ``forkOwner:headBranch``.
        """

    @abstractmethod
    def find_open_pr(
        self,
        repo: str,
        head: str,
        base: str,
        *,
        head_repo_owner: Optional[str] = None,
    ) -> Optional[int]:
        """Return PR number if an open PR already exists from *head* → *base*.

        *head* is the branch name (slashes allowed). *head_repo_owner* is the GitHub
        user/org that **owns the branch** — use when *repo* is the **base** repository
        but the head branch lives on a fork (open PR from fork → upstream).
        """

    @abstractmethod
    def find_open_pr_by_prefix(self, repo: str, head_prefix: str, base: str) -> Optional[int]:
        """Return the PR number of the first open PR whose head branch starts with
        *head_prefix* and targets *base*, or ``None`` if none found.

        Used to locate the remediation PR across re-scans where the head SHA
        (and therefore the exact branch name) may have changed.
        """

    @abstractmethod
    def get_pull_request_head_ref(self, repo: str, pr_number: int) -> str:
        """Return head/source branch **name** (ref) for the open PR."""

    @abstractmethod
    def update_pull_request_body(self, repo: str, pr_number: int, body: str, *, title: Optional[str] = None) -> None:
        """Update PR/MR description and optionally title."""

    # -- Commit status ------------------------------------------------------

    @abstractmethod
    def set_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "UniFAI PR Scan",
        target_url: str = "",
    ) -> None:
        """Post a commit status (pending / success / failure / error)."""

    # -- Labels -------------------------------------------------------------

    def get_bot_comment_body(self, repo: str, pr_number: int, marker: str) -> Optional[str]:
        """Return the full body of the first comment containing *marker*, or None."""
        return None

    def add_pr_label(self, repo: str, pr_number: int, label: str) -> None:
        """Create *label* in the repo if needed, then apply it to the PR."""

    def remove_pr_labels_prefixed(self, repo: str, pr_number: int, prefix: str) -> None:
        """Remove all labels whose name starts with *prefix* from the PR."""

    def get_parent_repo(self, repo: str) -> Optional[str]:
        """Return ``owner/repo`` of the upstream repo if *repo* is a fork, else ``None``.

        Providers that do not expose fork metadata should return ``None``.
        """
        return None


# ---------------------------------------------------------------------------
# GitHub implementation
# ---------------------------------------------------------------------------

class GitHubClient(SCMClient):
    """GitHub REST API v3 client.

    Pagination is handled automatically for endpoints that return lists.
    """

    DEFAULT_BASE_URL = "https://api.github.com"

    @staticmethod
    def _encoded_git_head_ref(branch_name: str) -> str:
        """Encode ``heads/<branch>`` for ``GET /repos/.../git/ref/{segment}``.

        Branch names containing ``/`` (e.g. ``remediation/unifai-repo-abc``) must be
        sent with slashes as ``%2F``; otherwise GitHub treats extra path segments as
        separate URL parts and ref resolution fails, breaking ``branch_exists`` and
        commits targeting that branch (Contents API PUT can return 404).
        """
        return urllib.parse.quote(f"heads/{branch_name}", safe="")

    def __init__(self, token: str, base_url: str = DEFAULT_BASE_URL) -> None:
        super().__init__(token, base_url)

    # -- helpers ------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "UniFAI-PR-Scanner/1.0",
        }

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        *,
        accept: Optional[str] = None,
        raw: bool = False,
        expected_errors: Optional[set] = None,
    ) -> Any:
        """Issue an HTTP request and return the decoded JSON (or raw bytes).

        *expected_errors* is an optional set of HTTP status codes (e.g. ``{404}``)
        that the caller expects and will handle — these are logged at DEBUG instead
        of ERROR so they don't pollute output during normal operation.
        """
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        headers = self._headers()
        if accept:
            headers["Accept"] = accept

        data = json.dumps(body).encode() if body else None
        if data:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        logger.debug("%s %s", method, url)

        try:
            with urllib.request.urlopen(req) as resp:
                resp_bytes = resp.read()
                if raw:
                    return resp_bytes
                if not resp_bytes:
                    return None
                return json.loads(resp_bytes)
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")[:500]
            if expected_errors and exc.code in expected_errors:
                logger.debug("GitHub API %s %s → %s (expected): %s", method, url, exc.code, error_body)
            else:
                logger.error("GitHub API %s %s → %s: %s", method, url, exc.code, error_body)
            raise

    def _get_paginated(self, path: str) -> List[Dict[str, Any]]:
        """Follow ``Link: <…>; rel="next"`` headers to collect all pages."""
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        results: List[Dict[str, Any]] = []
        while url:
            headers = self._headers()
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req) as resp:
                results.extend(json.loads(resp.read()))
                # Parse Link header for next page
                link_header = resp.headers.get("Link", "")
                url = self._parse_next_link(link_header)
        return results

    @staticmethod
    def _parse_next_link(link_header: str) -> Optional[str]:
        """Extract the ``next`` URL from a GitHub ``Link`` header."""
        if not link_header:
            return None
        for part in link_header.split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
                return url
        return None

    # -- PR metadata -------------------------------------------------------

    def get_pr_changed_files(self, repo: str, pr_number: int) -> List[ChangedFile]:
        raw_files = self._get_paginated(f"/repos/{repo}/pulls/{pr_number}/files")
        return [
            ChangedFile(
                filename=f["filename"],
                status=f.get("status", "modified"),
                sha=f.get("sha", ""),
                additions=f.get("additions", 0),
                deletions=f.get("deletions", 0),
                patch=f.get("patch", ""),
                previous_filename=f.get("previous_filename"),
            )
            for f in raw_files
        ]

    def get_pr_head_sha(self, repo: str, pr_number: int) -> Tuple[str, str]:
        resp = self._request("GET", f"/repos/{repo}/pulls/{pr_number}")
        head_sha = resp["head"]["sha"]
        base_branch = resp["base"]["ref"]
        return head_sha, base_branch

    def get_file_content(self, repo: str, path: str, ref: str) -> bytes:
        resp = self._request(
            "GET",
            f"/repos/{repo}/contents/{path}?ref={ref}",
        )
        if isinstance(resp, dict) and resp.get("content"):
            return base64.b64decode(resp["content"])
        raise ValueError(f"Unexpected response for {path}@{ref}: {type(resp)}")

    # -- Comments -----------------------------------------------------------

    def post_pr_comment(self, repo: str, pr_number: int, body: str) -> int:
        resp = self._request("POST", f"/repos/{repo}/issues/{pr_number}/comments", {"body": body})
        return resp["id"]

    def update_pr_comment(self, repo: str, comment_id: int, body: str) -> None:
        self._request("PATCH", f"/repos/{repo}/issues/comments/{comment_id}", {"body": body})

    def find_bot_comment(self, repo: str, pr_number: int, marker: str) -> Optional[int]:
        comments = self._get_paginated(f"/repos/{repo}/issues/{pr_number}/comments")
        for c in comments:
            if marker in c.get("body", ""):
                return c["id"]
        return None

    # -- Branches & commits -------------------------------------------------

    def create_branch(self, repo: str, branch_name: str, from_sha: str) -> None:
        self._request("POST", f"/repos/{repo}/git/refs", {
            "ref": f"refs/heads/{branch_name}",
            "sha": from_sha,
        })

    def branch_exists(self, repo: str, branch_name: str) -> bool:
        try:
            ref_seg = self._encoded_git_head_ref(branch_name)
            self._request("GET", f"/repos/{repo}/git/ref/{ref_seg}", expected_errors={404})
            return True
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            raise

    def get_file_blob_sha(self, repo: str, path: str, ref: str) -> Optional[str]:
        """Return the blob SHA for *path* at *ref*, or None if not found."""
        return self._github_file_blob_sha(repo, path, ref)

    def _github_file_blob_sha(self, repo: str, path: str, ref: str) -> Optional[str]:
        """Return the blob SHA for *path* at *ref*, or None if the file does not exist.

        GitHub requires this SHA when updating an existing file via the Contents API.
        Callers that omit *sha* on ``commit_file`` (e.g. full-repo scans) rely on this.
        """
        encoded_path = urllib.parse.quote(path, safe="/")
        qref = urllib.parse.quote(ref, safe="")
        try:
            data = self._request(
                "GET",
                f"/repos/{repo}/contents/{encoded_path}?ref={qref}",
                expected_errors={404},
            )
            if isinstance(data, dict) and data.get("type") == "file" and data.get("sha"):
                return str(data["sha"])
            return None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def commit_file(
        self,
        repo: str,
        branch: str,
        path: str,
        content: bytes,
        message: str,
        sha: Optional[str] = None,
    ) -> str:
        if sha is None:
            sha = self._github_file_blob_sha(repo, path, branch)
        payload: Dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        encoded_path = urllib.parse.quote(path, safe="/")
        resp = self._request("PUT", f"/repos/{repo}/contents/{encoded_path}", payload)
        return resp["commit"]["sha"]

    # -- Pull requests ------------------------------------------------------

    def create_pull_request(
        self,
        repo: str,
        title: str,
        head: str,
        base: str,
        body: str,
        *,
        cross_repo_head_owner: Optional[str] = None,
    ) -> int:
        head_payload = (
            f"{cross_repo_head_owner}:{head}"
            if cross_repo_head_owner
            else head
        )
        resp = self._request("POST", f"/repos/{repo}/pulls", {
            "title": title,
            "head": head_payload,
            "base": base,
            "body": body,
        })
        return resp["number"]

    def find_open_pr(
        self,
        repo: str,
        head: str,
        base: str,
        *,
        head_repo_owner: Optional[str] = None,
    ) -> Optional[int]:
        owner = head_repo_owner or repo.split("/", 1)[0]
        head_filter = f"{owner}:{head}"
        qs = urllib.parse.urlencode({"state": "open", "head": head_filter, "base": base})
        prs = self._get_paginated(f"/repos/{repo}/pulls?{qs}")
        if prs:
            return prs[0]["number"]
        return None

    def find_open_pr_by_prefix(self, repo: str, head_prefix: str, base: str) -> Optional[int]:
        prs = self._get_paginated(f"/repos/{repo}/pulls?state=open&base={base}")
        for pr in prs:
            head_branch = pr.get("head", {}).get("ref", "")
            if head_branch.startswith(head_prefix):
                return pr["number"]
        return None

    def get_pull_request_head_ref(self, repo: str, pr_number: int) -> str:
        resp = self._request("GET", f"/repos/{repo}/pulls/{pr_number}")
        return str(resp.get("head", {}).get("ref", ""))

    def update_pull_request_body(self, repo: str, pr_number: int, body: str, *, title: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {"body": body}
        if title is not None:
            payload["title"] = title
        self._request("PATCH", f"/repos/{repo}/pulls/{pr_number}", payload)

    # -- Commit status ------------------------------------------------------

    def set_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "UniFAI PR Scan",
        target_url: str = "",
    ) -> None:
        payload: Dict[str, Any] = {
            "state": state,
            "description": description[:140],  # GitHub limit
            "context": context,
        }
        if target_url:
            payload["target_url"] = target_url
        self._request("POST", f"/repos/{repo}/statuses/{sha}", payload)

    # -- Labels -------------------------------------------------------------

    def get_bot_comment_body(self, repo: str, pr_number: int, marker: str) -> Optional[str]:
        comments = self._get_paginated(f"/repos/{repo}/issues/{pr_number}/comments")
        for c in comments:
            body = c.get("body", "")
            if marker in body:
                return body
        return None

    def add_pr_label(self, repo: str, pr_number: int, label: str) -> None:
        # Create label in repo if it doesn't exist yet
        try:
            self._request("POST", f"/repos/{repo}/labels", {
                "name": label,
                "color": "0075ca",
                "description": "Applied by AIPO PR Scanner",
            })
        except urllib.error.HTTPError as exc:
            if exc.code != 422:  # 422 = label already exists
                logger.warning("Failed to create label %r: %s", label, exc)
        # Apply to the PR
        try:
            self._request("POST", f"/repos/{repo}/issues/{pr_number}/labels", {
                "labels": [label],
            })
            logger.debug("Applied label %r to PR #%d", label, pr_number)
        except Exception as exc:
            logger.warning("Failed to apply label %r to PR #%d: %s", label, pr_number, exc)

    def remove_pr_labels_prefixed(self, repo: str, pr_number: int, prefix: str) -> None:
        try:
            labels = self._get_paginated(f"/repos/{repo}/issues/{pr_number}/labels")
            for lbl in labels:
                name = lbl.get("name", "")
                if name.startswith(prefix):
                    try:
                        encoded = urllib.request.quote(name, safe="")
                        self._request("DELETE", f"/repos/{repo}/issues/{pr_number}/labels/{encoded}")
                        logger.debug("Removed label %r from PR #%d", name, pr_number)
                    except Exception as exc:
                        logger.warning("Failed to remove label %r: %s", name, exc)
        except Exception as exc:
            logger.warning("Failed to fetch labels for PR #%d: %s", pr_number, exc)

    def get_parent_repo(self, repo: str) -> Optional[str]:
        """Return the upstream ``owner/repo`` if *repo* is a GitHub fork, else ``None``."""
        try:
            info = self._request("GET", f"/repos/{repo}")
            if info and info.get("fork"):
                parent = (info.get("parent") or {}).get("full_name")
                if parent:
                    logger.info("Detected fork: %s → parent: %s", repo, parent)
                    return parent
        except Exception as exc:
            logger.warning("Could not determine parent repo for %s: %s", repo, exc)
        return None


# ---------------------------------------------------------------------------
# Bitbucket Cloud implementation
# ---------------------------------------------------------------------------

class BitbucketClient(SCMClient):
    """Bitbucket Cloud REST API 2.0 client.

    Pagination uses ``next`` field in the JSON response envelope.
    Repo identifiers are ``workspace/repo_slug`` (same as GitHub's ``owner/repo``).
    """

    DEFAULT_BASE_URL = "https://api.bitbucket.org/2.0"

    def __init__(self, token: str, base_url: str = DEFAULT_BASE_URL) -> None:
        super().__init__(token, base_url)

    # -- helpers ------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "UniFAI-PR-Scanner/1.0",
        }

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        *,
        raw: bool = False,
    ) -> Any:
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        headers = self._headers()
        data = json.dumps(body).encode() if body else None
        if data:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        logger.debug("%s %s", method, url)

        try:
            with urllib.request.urlopen(req) as resp:
                resp_bytes = resp.read()
                if raw:
                    return resp_bytes
                if not resp_bytes:
                    return None
                return json.loads(resp_bytes)
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")[:500]
            logger.error("Bitbucket API %s %s → %s: %s", method, url, exc.code, error_body)
            raise

    def _get_paginated(self, path: str) -> List[Dict[str, Any]]:
        """Follow Bitbucket's ``next`` field for pagination."""
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        results: List[Dict[str, Any]] = []
        while url:
            resp = self._request("GET", url)
            values = resp.get("values", []) if isinstance(resp, dict) else resp
            results.extend(values)
            url = resp.get("next") if isinstance(resp, dict) else None
        return results

    # -- PR metadata -------------------------------------------------------

    def get_pr_changed_files(self, repo: str, pr_number: int) -> List[ChangedFile]:
        raw_files = self._get_paginated(
            f"/repositories/{repo}/pullrequests/{pr_number}/diffstat",
        )
        files = []
        for f in raw_files:
            new_path = f.get("new", {})
            old_path = f.get("old", {})
            filename = (new_path.get("path") if new_path else None) or (
                old_path.get("path") if old_path else ""
            )
            status_raw = f.get("status", "modified")
            # Bitbucket statuses: added, removed, modified, renamed
            status = status_raw if status_raw in ("added", "removed", "modified", "renamed") else "modified"
            previous = old_path.get("path") if status == "renamed" and old_path else None
            files.append(ChangedFile(
                filename=filename,
                status=status,
                sha="",  # Bitbucket diffstat doesn't include blob SHA
                additions=f.get("lines_added", 0),
                deletions=f.get("lines_removed", 0),
                previous_filename=previous,
            ))
        return files

    def get_pr_head_sha(self, repo: str, pr_number: int) -> Tuple[str, str]:
        resp = self._request("GET", f"/repositories/{repo}/pullrequests/{pr_number}")
        head_sha = resp["source"]["commit"]["hash"]
        base_branch = resp["destination"]["branch"]["name"]
        return head_sha, base_branch

    def get_file_content(self, repo: str, path: str, ref: str) -> bytes:
        # Bitbucket returns raw file content at this endpoint
        resp_bytes = self._request(
            "GET", f"/repositories/{repo}/src/{ref}/{path}", raw=True,
        )
        if isinstance(resp_bytes, bytes):
            return resp_bytes
        raise ValueError(f"Unexpected response for {path}@{ref}")

    # -- Comments -----------------------------------------------------------

    def post_pr_comment(self, repo: str, pr_number: int, body: str) -> int:
        resp = self._request(
            "POST",
            f"/repositories/{repo}/pullrequests/{pr_number}/comments",
            {"content": {"raw": body}},
        )
        return resp["id"]

    def update_pr_comment(self, repo: str, comment_id: int, body: str) -> None:
        # Bitbucket needs the PR number for the URL — we store it using a
        # workaround: comment_id is globally unique so we use the direct endpoint.
        # However, Bitbucket requires the PR number.  We work around this by
        # storing PR number in the comment marker search and passing repo-level.
        # NOTE: Bitbucket comment update requires PR number.  The caller must
        # track this.  For now, comment_id is enough for the update endpoint
        # which is at: /repositories/{repo}/pullrequests/{pr_id}/comments/{comment_id}
        # We'll handle this via a helper that also passes pr_number.
        raise NotImplementedError(
            "Bitbucket requires PR number for comment update. "
            "Use update_pr_comment_with_pr() instead."
        )

    def update_pr_comment_with_pr(
        self, repo: str, pr_number: int, comment_id: int, body: str,
    ) -> None:
        """Update a comment on a specific PR (Bitbucket requires PR number)."""
        self._request(
            "PUT",
            f"/repositories/{repo}/pullrequests/{pr_number}/comments/{comment_id}",
            {"content": {"raw": body}},
        )

    def find_bot_comment(self, repo: str, pr_number: int, marker: str) -> Optional[int]:
        comments = self._get_paginated(
            f"/repositories/{repo}/pullrequests/{pr_number}/comments",
        )
        for c in comments:
            content = c.get("content", {}).get("raw", "")
            if marker in content:
                return c["id"]
        return None

    # -- Branches & commits -------------------------------------------------

    def create_branch(self, repo: str, branch_name: str, from_sha: str) -> None:
        self._request("POST", f"/repositories/{repo}/refs/branches", {
            "name": branch_name,
            "target": {"hash": from_sha},
        })

    def branch_exists(self, repo: str, branch_name: str) -> bool:
        try:
            self._request("GET", f"/repositories/{repo}/refs/branches/{branch_name}")
            return True
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            raise

    def commit_file(
        self,
        repo: str,
        branch: str,
        path: str,
        content: bytes,
        message: str,
        sha: Optional[str] = None,
    ) -> str:
        """Commit a file to a branch via Bitbucket's source endpoint.


        Uses multipart/form-data via the /src endpoint.
        """
        # Bitbucket uses a form-data POST to /repositories/{repo}/src
        boundary = "----UniFAIBoundary"
        parts = []

        # File content part
        parts.append(f"--{boundary}")
        parts.append(f'Content-Disposition: form-data; name="{path}"; filename="{path}"')
        parts.append("Content-Type: application/octet-stream")
        parts.append("")
        # We'll handle binary content separately

        # Message part
        msg_parts = []
        msg_parts.append(f"--{boundary}")
        msg_parts.append('Content-Disposition: form-data; name="message"')
        msg_parts.append("")
        msg_parts.append(message)

        # Branch part
        msg_parts.append(f"--{boundary}")
        msg_parts.append('Content-Disposition: form-data; name="branch"')
        msg_parts.append("")
        msg_parts.append(branch)
        msg_parts.append(f"--{boundary}--")

        # Build the body manually to handle binary content
        header_text = "\r\n".join([
            f"--{boundary}",
            f'Content-Disposition: form-data; name="{path}"; filename="{path}"',
            "Content-Type: application/octet-stream",
            "",
        ]).encode()
        footer_text = "\r\n".join([
            "",
            f"--{boundary}",
            'Content-Disposition: form-data; name="message"',
            "",
            message,
            f"--{boundary}",
            'Content-Disposition: form-data; name="branch"',
            "",
            branch,
            f"--{boundary}--",
            "",
        ]).encode()

        body = header_text + content + footer_text

        url = f"{self.base_url}/repositories/{repo}/src"
        headers = self._headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        del headers["Accept"]  # Bitbucket /src returns 201 with no JSON body sometimes

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                # Bitbucket may or may not return a response body
                resp_bytes = resp.read()
                if resp_bytes:
                    result = json.loads(resp_bytes)
                    return result.get("hash", "")
                return ""
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")[:500]
            logger.error("Bitbucket commit failed: %s: %s", exc.code, error_body)
            raise

    # -- Pull requests ------------------------------------------------------

    def create_pull_request(
        self,
        repo: str,
        title: str,
        head: str,
        base: str,
        body: str,
        *,
        cross_repo_head_owner: Optional[str] = None,
    ) -> int:
        if cross_repo_head_owner:
            logger.warning(
                "Bitbucket: cross_repo_head_owner is set but fork→upstream PR wiring is unsupported; "
                "opening MR in repo %s as usual.",
                repo,
            )
        resp = self._request("POST", f"/repositories/{repo}/pullrequests", {
            "title": title,
            "source": {"branch": {"name": head}},
            "destination": {"branch": {"name": base}},
            "description": body,
        })
        return resp["id"]

    def find_open_pr(
        self,
        repo: str,
        head: str,
        base: str,
        *,
        head_repo_owner: Optional[str] = None,
    ) -> Optional[int]:
        _ = head_repo_owner  # Bitbucket resolves source repo from branch + workspace
        prs = self._get_paginated(
            f"/repositories/{repo}/pullrequests?state=OPEN",
        )
        for pr in prs:
            src = pr.get("source", {}).get("branch", {}).get("name", "")
            dst = pr.get("destination", {}).get("branch", {}).get("name", "")
            if src == head and dst == base:
                return pr["id"]
        return None

    def find_open_pr_by_prefix(self, repo: str, head_prefix: str, base: str) -> Optional[int]:
        prs = self._get_paginated(f"/repositories/{repo}/pullrequests?state=OPEN")
        for pr in prs:
            src = pr.get("source", {}).get("branch", {}).get("name", "")
            dst = pr.get("destination", {}).get("branch", {}).get("name", "")
            if src.startswith(head_prefix) and dst == base:
                return pr["id"]
        return None

    def get_pull_request_head_ref(self, repo: str, pr_number: int) -> str:
        resp = self._request("GET", f"/repositories/{repo}/pullrequests/{pr_number}")
        return str(resp.get("source", {}).get("branch", {}).get("name", ""))

    def update_pull_request_body(self, repo: str, pr_number: int, body: str, *, title: Optional[str] = None) -> None:
        cur = self._request("GET", f"/repositories/{repo}/pullrequests/{pr_number}")
        payload: Dict[str, Any] = {
            "version": cur["version"],
            "description": body,
        }
        if title is not None:
            payload["title"] = title
        self._request("PUT", f"/repositories/{repo}/pullrequests/{pr_number}", payload)

    # -- Commit status ------------------------------------------------------

    def set_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "UniFAI PR Scan",
        target_url: str = "",
    ) -> None:
        # Bitbucket uses SUCCESSFUL/FAILED/INPROGRESS/STOPPED
        state_map = {
            "pending": "INPROGRESS",
            "success": "SUCCESSFUL",
            "failure": "FAILED",
            "error": "STOPPED",
        }
        bb_state = state_map.get(state, "INPROGRESS")
        payload: Dict[str, Any] = {
            "state": bb_state,
            "key": context.replace(" ", "-"),
            "name": context,
            "description": description[:255],
        }
        if target_url:
            payload["url"] = target_url
        self._request(
            "POST", f"/repositories/{repo}/commit/{sha}/statuses/build", payload,
        )


# ---------------------------------------------------------------------------
# GitLab implementation
# ---------------------------------------------------------------------------

class GitLabClient(SCMClient):
    """GitLab REST API v4 client.

    Repo identifiers are URL-encoded project paths (e.g. ``group%2Fproject``)
    or numeric project IDs.  This client accepts ``group/project`` and
    URL-encodes it internally.

    Pagination uses the ``x-next-page`` response header.
    """

    DEFAULT_BASE_URL = "https://gitlab.com/api/v4"

    def __init__(self, token: str, base_url: str = DEFAULT_BASE_URL) -> None:
        super().__init__(token, base_url)

    @staticmethod
    def _encode_project(repo: str) -> str:
        """URL-encode a ``group/project`` path for GitLab API URLs."""
        return urllib.request.quote(repo, safe="")

    # -- helpers ------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "PRIVATE-TOKEN": self.token,
            "Accept": "application/json",
            "User-Agent": "UniFAI-PR-Scanner/1.0",
        }

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        *,
        raw: bool = False,
    ) -> Any:
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        headers = self._headers()
        data = json.dumps(body).encode() if body else None
        if data:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        logger.debug("%s %s", method, url)

        try:
            with urllib.request.urlopen(req) as resp:
                resp_bytes = resp.read()
                if raw:
                    return resp_bytes
                if not resp_bytes:
                    return None
                return json.loads(resp_bytes)
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")[:500]
            logger.error("GitLab API %s %s → %s: %s", method, url, exc.code, error_body)
            raise

    def _get_paginated(self, path: str) -> List[Dict[str, Any]]:
        """Follow GitLab's ``x-next-page`` header for pagination."""
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        # Ensure per_page is set for efficiency
        sep = "&" if "?" in url else "?"
        if "per_page" not in url:
            url = f"{url}{sep}per_page=100"
        results: List[Dict[str, Any]] = []
        while url:
            headers = self._headers()
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req) as resp:
                results.extend(json.loads(resp.read()))
                next_page = resp.headers.get("x-next-page", "")
                if next_page and next_page.strip():
                    # Reconstruct URL with next page
                    if "page=" in url:
                        import re
                        url = re.sub(r"page=\d+", f"page={next_page}", url)
                    else:
                        url = f"{url}&page={next_page}"
                else:
                    url = None  # type: ignore[assignment]
        return results

    # -- PR metadata (GitLab calls them Merge Requests) ---------------------

    def get_pr_changed_files(self, repo: str, pr_number: int) -> List[ChangedFile]:
        project = self._encode_project(repo)
        raw_changes = self._get_paginated(
            f"/projects/{project}/merge_requests/{pr_number}/changes",
        )
        # The /changes endpoint returns a single MR object with a "changes" array
        # when not paginated.  When paginated, it returns the changes array directly.
        changes = []
        if isinstance(raw_changes, list) and raw_changes and "changes" in raw_changes[0]:
            changes = raw_changes[0].get("changes", [])
        elif isinstance(raw_changes, list):
            changes = raw_changes
        elif isinstance(raw_changes, dict):
            changes = raw_changes.get("changes", [])

        files = []
        for c in changes:
            new_path = c.get("new_path", "")
            old_path = c.get("old_path", "")
            new_file = c.get("new_file", False)
            deleted = c.get("deleted_file", False)
            renamed = c.get("renamed_file", False)

            if deleted:
                status = "removed"
            elif new_file:
                status = "added"
            elif renamed:
                status = "renamed"
            else:
                status = "modified"

            files.append(ChangedFile(
                filename=new_path or old_path,
                status=status,
                sha="",
                previous_filename=old_path if renamed else None,
            ))
        return files

    def get_pr_head_sha(self, repo: str, pr_number: int) -> Tuple[str, str]:
        project = self._encode_project(repo)
        resp = self._request("GET", f"/projects/{project}/merge_requests/{pr_number}")
        head_sha = resp["sha"]
        base_branch = resp["target_branch"]
        return head_sha, base_branch

    def get_file_content(self, repo: str, path: str, ref: str) -> bytes:
        project = self._encode_project(repo)
        encoded_path = urllib.request.quote(path, safe="")
        resp_bytes = self._request(
            "GET",
            f"/projects/{project}/repository/files/{encoded_path}/raw?ref={ref}",
            raw=True,
        )
        if isinstance(resp_bytes, bytes):
            return resp_bytes
        raise ValueError(f"Unexpected response for {path}@{ref}")

    # -- Comments (MR notes) ------------------------------------------------

    def post_pr_comment(self, repo: str, pr_number: int, body: str) -> int:
        project = self._encode_project(repo)
        resp = self._request(
            "POST",
            f"/projects/{project}/merge_requests/{pr_number}/notes",
            {"body": body},
        )
        return resp["id"]

    def update_pr_comment(self, repo: str, comment_id: int, body: str) -> None:
        # GitLab note update requires project + MR iid + note id.
        # Since we don't have MR iid here, we raise like Bitbucket.
        raise NotImplementedError(
            "GitLab requires MR iid for note update. "
            "Use update_pr_comment_with_pr() instead."
        )

    def update_pr_comment_with_pr(
        self, repo: str, pr_number: int, comment_id: int, body: str,
    ) -> None:
        """Update a note on a specific merge request."""
        project = self._encode_project(repo)
        self._request(
            "PUT",
            f"/projects/{project}/merge_requests/{pr_number}/notes/{comment_id}",
            {"body": body},
        )

    def find_bot_comment(self, repo: str, pr_number: int, marker: str) -> Optional[int]:
        project = self._encode_project(repo)
        notes = self._get_paginated(
            f"/projects/{project}/merge_requests/{pr_number}/notes",
        )
        for n in notes:
            if marker in n.get("body", ""):
                return n["id"]
        return None

    # -- Branches & commits -------------------------------------------------

    def create_branch(self, repo: str, branch_name: str, from_sha: str) -> None:
        project = self._encode_project(repo)
        self._request("POST", f"/projects/{project}/repository/branches", {
            "branch": branch_name,
            "ref": from_sha,
        })

    def branch_exists(self, repo: str, branch_name: str) -> bool:
        project = self._encode_project(repo)
        try:
            encoded_branch = urllib.request.quote(branch_name, safe="")
            self._request("GET", f"/projects/{project}/repository/branches/{encoded_branch}")
            return True
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            raise

    def commit_file(
        self,
        repo: str,
        branch: str,
        path: str,
        content: bytes,
        message: str,
        sha: Optional[str] = None,
    ) -> str:
        """Create or update a file via GitLab's commits API."""
        project = self._encode_project(repo)
        # Determine action: if sha provided, it's an update; otherwise create
        action = "update" if sha else "create"
        payload = {
            "branch": branch,
            "commit_message": message,
            "actions": [{
                "action": action,
                "file_path": path,
                "content": base64.b64encode(content).decode(),
                "encoding": "base64",
            }],
        }
        resp = self._request("POST", f"/projects/{project}/repository/commits", payload)
        return resp.get("id", "")

    # -- Pull requests (Merge Requests) -------------------------------------

    def create_pull_request(
        self,
        repo: str,
        title: str,
        head: str,
        base: str,
        body: str,
        *,
        cross_repo_head_owner: Optional[str] = None,
    ) -> int:
        if cross_repo_head_owner:
            logger.warning(
                "GitLab: cross_repo_head_owner is set but fork→upstream MR wiring is unsupported; "
                "opening MR in project %s as usual.",
                repo,
            )
        project = self._encode_project(repo)
        resp = self._request("POST", f"/projects/{project}/merge_requests", {
            "title": title,
            "source_branch": head,
            "target_branch": base,
            "description": body,
        })
        return resp["iid"]

    def find_open_pr(
        self,
        repo: str,
        head: str,
        base: str,
        *,
        head_repo_owner: Optional[str] = None,
    ) -> Optional[int]:
        _ = head_repo_owner
        project = self._encode_project(repo)
        enc_head = urllib.parse.quote(head, safe="")
        enc_base = urllib.parse.quote(base, safe="")
        mrs = self._get_paginated(
            f"/projects/{project}/merge_requests?state=opened"
            f"&source_branch={enc_head}&target_branch={enc_base}",
        )
        if mrs:
            return mrs[0]["iid"]
        return None

    def find_open_pr_by_prefix(self, repo: str, head_prefix: str, base: str) -> Optional[int]:
        project = self._encode_project(repo)
        mrs = self._get_paginated(
            f"/projects/{project}/merge_requests?state=opened&target_branch={base}"
        )
        for mr in mrs:
            if mr.get("source_branch", "").startswith(head_prefix):
                return mr["iid"]
        return None

    def get_pull_request_head_ref(self, repo: str, pr_number: int) -> str:
        project = self._encode_project(repo)
        resp = self._request("GET", f"/projects/{project}/merge_requests/{pr_number}")
        return str(resp.get("source_branch", ""))

    def update_pull_request_body(self, repo: str, pr_number: int, body: str, *, title: Optional[str] = None) -> None:
        project = self._encode_project(repo)
        payload_gl: Dict[str, Any] = {"description": body}
        if title is not None:
            payload_gl["title"] = title
        self._request("PUT", f"/projects/{project}/merge_requests/{pr_number}", payload_gl)

    # -- Commit status (pipeline status) ------------------------------------

    def set_commit_status(
        self,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "UniFAI PR Scan",
        target_url: str = "",
    ) -> None:
        project = self._encode_project(repo)
        # GitLab uses: pending, running, success, failed, canceled
        state_map = {
            "pending": "pending",
            "success": "success",
            "failure": "failed",
            "error": "failed",
        }
        gl_state = state_map.get(state, "pending")
        payload: Dict[str, Any] = {
            "state": gl_state,
            "name": context,
            "description": description[:255],
        }
        if target_url:
            payload["target_url"] = target_url
        self._request(
            "POST", f"/projects/{project}/statuses/{sha}", payload,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

#: Map of provider names to their default base URLs.
_PROVIDER_DEFAULTS: Dict[str, Tuple[type, str]] = {
    "github": (GitHubClient, GitHubClient.DEFAULT_BASE_URL),
    "bitbucket": (BitbucketClient, BitbucketClient.DEFAULT_BASE_URL),
    "gitlab": (GitLabClient, GitLabClient.DEFAULT_BASE_URL),
}


def create_scm_client(
    provider: str,
    token: str,
    base_url: str = "",
) -> SCMClient:
    """Create an SCM client for the given provider.

    Args:
        provider: One of ``github``, ``bitbucket``, ``gitlab``.
        token: Access token for the SCM API.
        base_url: Optional override for the API base URL (e.g. for
            GitHub Enterprise, self-hosted GitLab/Bitbucket).

    Returns:
        An :class:`SCMClient` instance.

    Raises:
        ValueError: If the provider is not supported.
    """
    key = provider.lower().strip()
    if key not in _PROVIDER_DEFAULTS:
        supported = ", ".join(sorted(_PROVIDER_DEFAULTS))
        raise ValueError(f"Unsupported SCM provider: {provider!r}. Supported: {supported}")
    cls, default_url = _PROVIDER_DEFAULTS[key]
    return cls(token=token, base_url=base_url or default_url)
