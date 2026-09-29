"""Bounded GitHub Git-object access and exact-byte commit reconciliation."""
import base64
import json
import re
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise ValueError(message)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("GitHub API redirects are forbidden")

class GitHubRepository:
    """Git objects plus non-forced ref advance; no overwrite on competing commits."""
    def __init__(self, name, token, private):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name) is not None, "Invalid repository")
        require(bool(token) or private is False, "Missing repository-scoped credential")
        self.name, self.token = name, token
        self.opener = urllib.request.build_opener(NoRedirect())
        metadata = self.api("GET", "")
        require(metadata["full_name"] == name and metadata["private"] is private and metadata["default_branch"] == "main",
                "Repository identity, visibility or branch mismatch")

    def api(self, method, path, body=None):
        require(bool(self.token) or (method == "GET" and body is None), "Anonymous repository access is read-only")
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request("https://api.github.com/repos/" + self.name + path, data=data, method=method,
            headers={**({"Authorization": "Bearer " + self.token} if self.token else {}), "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json", "User-Agent": "Decian-Update-Publisher/1"})
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
                require(len(raw) <= 16 * 1024 * 1024, "GitHub response exceeds limit")
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            # Never include headers, body, credential or signed URL in errors.
            raise RuntimeError("GitHub publication request failed: HTTP " + str(error.code)) from None

    def snapshot(self):
        sha = self.api("GET", "/git/ref/heads/main")["object"]["sha"]
        commit = self.api("GET", "/git/commits/" + sha)
        tree = self.api("GET", "/git/trees/" + commit["tree"]["sha"] + "?recursive=1")
        require(not tree.get("truncated"), "Repository tree is truncated")
        return {"sha": sha, "tree": commit["tree"]["sha"], "entries": {e["path"]: e for e in tree["tree"]}}

    def read(self, snapshot, path):
        entry = snapshot["entries"].get(path)
        if entry is None:
            return None
        require(entry["type"] == "blob" and entry["mode"] == "100644", "Publication path is not a regular file")
        blob = self.api("GET", "/git/blobs/" + entry["sha"])
        require(blob["encoding"] == "base64" and blob["size"] <= 65536, "Publication blob exceeds limit")
        data = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
        require(len(data) == blob["size"], "Blob length mismatch")
        return data

    def commit(self, snapshot, files, message):
        entries = []
        for path, data in files.items():
            blob = self.api("POST", "/git/blobs", {"encoding": "base64", "content": base64.b64encode(data).decode()})
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        tree = self.api("POST", "/git/trees", {"base_tree": snapshot["tree"], "tree": entries})
        commit = self.api("POST", "/git/commits", {"tree": tree["sha"], "parents": [snapshot["sha"]], "message": message})
        # The single parent plus force:false makes a concurrent main advance reject this commit.
        self.api("PATCH", "/git/refs/heads/main", {"sha": commit["sha"], "force": False})


def reconcile(repo, snapshot, files, message):
    """A lost reply is success only if a fresh snapshot contains EVERY exact byte."""
    try:
        repo.commit(snapshot, files, message)
    except (RuntimeError, OSError):
        latest = repo.snapshot()
        require(all(repo.read(latest, p) == b for p, b in files.items()),
                "Publication not confirmed; retry with the same durable intent")
        return latest
    latest = repo.snapshot()
    require(all(repo.read(latest, p) == b for p, b in files.items()), "Publication readback differs; stop and investigate")
    return latest

