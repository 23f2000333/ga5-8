from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import requests
import socket
import ipaddress

app = FastAPI()

# Sandbox root
SANDBOX = Path("/srv/agent-redteam/sandbox-903d309709").resolve()

# Only these hosts are allowed
ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


# -----------------------------
# Safe File Read
# -----------------------------
def safe_read(path_str: str) -> str:
    """
    Only allow reads inside the sandbox directory.
    """

    requested = (SANDBOX / path_str).resolve()

    try:
        requested.relative_to(SANDBOX)
    except ValueError:
        raise PermissionError("outside sandbox")

    if not requested.is_file():
        raise FileNotFoundError("file not found")

    return requested.read_text(encoding="utf-8")


# -----------------------------
# URL Validation
# -----------------------------
def validate_url(url: str):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise PermissionError("invalid scheme")

    # Reject URLs like:
    # https://example.com@evil.com
    if parsed.username or parsed.password:
        raise PermissionError("userinfo not allowed")

    host = parsed.hostname

    if host not in ALLOWED_HOSTS:
        raise PermissionError("host not allowed")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise PermissionError("cannot resolve host")

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise PermissionError("resolved to non-public IP")

    return host


# -----------------------------
# Safe URL Fetch
# -----------------------------
def safe_fetch(url: str) -> str:
    validate_url(url)

    response = requests.get(
        url,
        timeout=5,
        allow_redirects=False,
        headers={
            "User-Agent": "GuardrailEndpoint/1.0"
        },
    )

    response.raise_for_status()

    return response.text


# -----------------------------
# Endpoint
# -----------------------------
@app.post("/check")
def check(req: ToolRequest):

    try:

        if req.tool == "read_file":

            path = req.arguments.get("path")
            if path is None:
                raise ValueError("missing path")

            result = safe_read(path)

            return {
                "action": "allow",
                "reason": "path inside sandbox",
                "result": result,
            }

        elif req.tool == "fetch_url":

            url = req.arguments.get("url")
            if url is None:
                raise ValueError("missing url")

            result = safe_fetch(url)

            return {
                "action": "allow",
                "reason": "allowed host",
                "result": result,
            }

        else:

            return {
                "action": "block",
                "reason": "unknown tool",
                "result": None,
            }

    except Exception as e:

        return {
            "action": "block",
            "reason": str(e),
            "result": None,
        }


@app.get("/")
def root():
    return {"status": "ok"}
