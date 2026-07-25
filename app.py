from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import requests
import socket
import ipaddress

app = FastAPI()

SANDBOX = Path("/srv/agent-redteam/sandbox-903d309709").resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def safe_read(path_str: str):

    p = (SANDBOX / path_str).resolve()

    try:
        p.relative_to(SANDBOX)
    except ValueError:
        raise PermissionError("outside sandbox")

    if not p.exists():
        raise FileNotFoundError("file not found")

    return p.read_text(encoding="utf-8")


def validate_url(url):

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise PermissionError("invalid scheme")

    if parsed.username or parsed.password:
        raise PermissionError("userinfo not allowed")

    host = parsed.hostname

    if host not in ALLOWED_HOSTS:
        raise PermissionError("host not allowed")

    infos = socket.getaddrinfo(host, None)

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
            raise PermissionError("private address")

    return host


def safe_fetch(url):

    validate_url(url)

    r = requests.get(
        url,
        timeout=5,
        allow_redirects=False,
        headers={
            "User-Agent": "guardrail"
        }
    )

    return r.text


@app.post("/check")
def check(req: ToolRequest):

    try:

        if req.tool == "read_file":

            result = safe_read(req.arguments["path"])

            return {
                "action": "allow",
                "reason": "inside sandbox",
                "result": {
                    "text": result
                }
            }

        elif req.tool == "fetch_url":

            result = safe_fetch(req.arguments["url"])

            return {
                "action": "allow",
                "reason": "allowed host",
                "result": {
                    "text": result
                }
            }

        return {
            "action": "block",
            "reason": "unknown tool",
            "result": None
        }

    except Exception as e:

        return {
            "action": "block",
            "reason": str(e),
            "result": None
        }


@app.get("/")
def root():
    return {"status": "ok"}
