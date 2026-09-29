"""
Warden over HTTP.

The same enforcement, in front of a server reached over the network instead of
a pipe. Every security decision comes from the shared guard, so HTTP is a way
of moving bytes rather than a second copy of the security logic.

What changes from stdio:

    Requests and replies are paired by the HTTP exchange itself, so Warden
    always knows what a response is a response to.

    Several requests can be in flight at once, on different threads.

    A reply may arrive as JSON or as a stream of server-sent events, and both
    can carry a tool list that needs inspecting.

    Sessions exist. The server issues an Mcp-Session-Id and expects it back.
    Warden passes it through untouched; it is the server's identifier, not
    Warden's to invent or interpret.

Warden binds to the loopback interface by default. A security proxy that is
reachable from the network by accident is a hole, not a control.

Usage:
    python -m warden.http_proxy --upstream https://example.com/mcp --name acme
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .enforcer import Enforcer
from .guard import MessageGuard
from .paths import audit_db, ensure_data_dir, registry_db
from .policy import load_policy
from .registry import ContractRegistry

# Headers Warden relays in each direction. An allowlist rather than a copy of
# everything: hop-by-hop headers break when proxied, and a blanket copy is how
# a proxy leaks something it never meant to.
FORWARD_TO_SERVER = (
    "content-type", "accept", "mcp-session-id", "mcp-protocol-version",
    "authorization", "last-event-id",
)
FORWARD_TO_CLIENT = (
    "content-type", "mcp-session-id", "mcp-protocol-version", "cache-control",
)

MAX_BODY_BYTES = 8 * 1024 * 1024


def log(msg: str) -> None:
    print(f"[warden:http] {msg}", file=sys.stderr, flush=True)


class UpstreamReply:
    """What came back from the server, before Warden decides what to pass on."""

    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return ""

    @property
    def is_event_stream(self) -> bool:
        return "text/event-stream" in self.header("content-type").lower()

    @property
    def is_json(self) -> bool:
        return "application/json" in self.header("content-type").lower()


class WardenHTTPProxy:
    """Holds the upstream target and the shared guard. One per server."""

    def __init__(self, upstream: str, guard: MessageGuard, timeout: float = 60.0):
        self.upstream = upstream
        self.guard = guard
        self.timeout = timeout
        self.lock = threading.Lock()
        self.refresh_in_flight = False
        self.session_id = ""

    # ---------- talking to the server ----------

    def send_upstream(self, body: bytes, headers: dict[str, str]) -> UpstreamReply:
        request = urllib.request.Request(self.upstream, data=body, method="POST")
        for key, value in headers.items():
            if key.lower() in FORWARD_TO_SERVER and value:
                request.add_header(key, value)

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return UpstreamReply(
                    response.status, list(response.headers.items()), response.read()
                )
        except urllib.error.HTTPError as exc:
            # The server answered, unhappily. Relay its answer rather than
            # inventing one, so the client sees what actually happened.
            return UpstreamReply(exc.code, list(exc.headers.items()), exc.read())

    # ---------- inspecting what comes back ----------

    def inspect_payload(self, payload: Any, asked: dict[Any, str]) -> Any:
        """
        Apply the guard to one decoded JSON-RPC payload, which may be a single
        message or a batch. Returns what the client should receive.
        """
        if isinstance(payload, list):
            return [self.inspect_payload(item, asked) for item in payload]
        if not isinstance(payload, dict):
            return payload

        method = asked.get(payload.get("id"))

        if method == "initialize" and "result" in payload:
            self.guard.note_initialize(payload["result"])

        if method == "tools/list" and "result" in payload:
            original = payload["result"].get("tools") or []
            payload["result"]["tools"] = self.guard.inspect_tool_list(original)

        if MessageGuard.is_list_changed(payload):
            self.guard.stats["announcements"] += 1
            threading.Thread(
                target=self.refresh_tool_list,
                args=(dict(asked),),
                daemon=True,
            ).start()

        return payload

    def inspect_event_stream(self, body: bytes, asked: dict[Any, str]) -> bytes:
        """
        Apply the guard to a server-sent event stream.

        Each event's data line carries a JSON-RPC payload, so the same
        inspection applies. Everything that is not a data line is relayed
        untouched, because the framing belongs to the server.
        """
        out: list[str] = []
        for raw in body.decode("utf-8", errors="replace").split("\n"):
            if not raw.startswith("data:"):
                out.append(raw)
                continue
            data = raw[5:].strip()
            if not data:
                out.append(raw)
                continue
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                out.append(raw)
                continue
            out.append("data: " + json.dumps(self.inspect_payload(payload, asked)))
        return "\n".join(out).encode("utf-8")

    # ---------- Warden's own request ----------

    def refresh_tool_list(self, asked: dict[Any, str]) -> None:
        """
        Ask the server for its tool list after it announces a change.

        The client never sees this exchange. It did not ask for it, and the
        point is that Warden should not have to wait until it does.
        """
        with self.lock:
            if self.refresh_in_flight:
                return
            self.refresh_in_flight = True

        try:
            request_id = "warden-refresh"
            body = json.dumps(
                {"jsonrpc": "2.0", "id": request_id, "method": "tools/list"}
            ).encode("utf-8")
            headers = {"content-type": "application/json", "accept": "application/json"}
            if self.session_id:
                headers["mcp-session-id"] = self.session_id

            log("re-checking the tool list (server announced a change)")
            reply = self.send_upstream(body, headers)
            if reply.is_json:
                payload = json.loads(reply.body.decode("utf-8"))
                self.inspect_payload(payload, {request_id: "tools/list"})
                log("re-check complete")
            else:
                log(f"re-check returned {reply.status} with no usable body")
        except Exception as exc:  # noqa: BLE001 - never let a refresh kill the proxy
            log(f"re-check failed: {exc}")
        finally:
            with self.lock:
                self.refresh_in_flight = False


def make_handler(proxy: WardenHTTPProxy):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Warden"

        def log_message(self, fmt, *args):  # quieter than the default
            pass

        # ---------- helpers ----------

        def relay(self, reply: UpstreamReply, body: bytes) -> None:
            self.send_response(reply.status)
            for key, value in reply.headers:
                if key.lower() in FORWARD_TO_CLIENT:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def refuse(self, status: int, message: str) -> None:
            body = json.dumps({"error": {"code": -32600, "message": message}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # ---------- the request path ----------

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                # Refuse rather than read it. An unbounded read is how a proxy
                # becomes the easiest thing in the stack to knock over.
                self.refuse(413, "request body too large")
                return

            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Warden fails closed. A body it cannot read is a body it
                # cannot check, so it does not reach the server.
                self.refuse(400, "body is not valid JSON, refusing to relay it")
                return

            messages = payload if isinstance(payload, list) else [payload]
            asked: dict[Any, str] = {}
            allowed: list[dict] = []
            denials: list[dict] = []

            for message in messages:
                if not isinstance(message, dict):
                    continue
                method = message.get("method")
                if method and message.get("id") is not None:
                    asked[message["id"]] = method

                if method == "tools/call":
                    ok, denial = proxy.guard.judge_tool_call(message)
                    if ok:
                        allowed.append(message)
                    else:
                        denials.append(denial)
                else:
                    allowed.append(message)

            # Nothing survived the check: answer the client directly and never
            # contact the server at all.
            if not allowed:
                body = json.dumps(
                    denials if isinstance(payload, list) else denials[0]
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if proxy.session_id:
                    self.send_header("Mcp-Session-Id", proxy.session_id)
                self.end_headers()
                self.wfile.write(body)
                return

            forward = allowed if isinstance(payload, list) else allowed[0]
            reply = proxy.send_upstream(
                json.dumps(forward).encode("utf-8"), dict(self.headers)
            )

            session = reply.header("mcp-session-id")
            if session:
                proxy.session_id = session

            if reply.is_event_stream:
                body = proxy.inspect_event_stream(reply.body, asked)
            elif reply.is_json and reply.body:
                try:
                    body = json.dumps(
                        proxy.inspect_payload(
                            json.loads(reply.body.decode("utf-8")), asked
                        )
                    ).encode("utf-8")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # The server said JSON and sent something else. Warden will
                    # not pass on a body it could not inspect.
                    self.refuse(502, "server sent a malformed JSON body")
                    return
            else:
                body = reply.body

            if denials:
                # Some of the batch was refused. Those replies are Warden's,
                # and they travel back alongside the server's.
                try:
                    merged = json.loads(body.decode("utf-8")) if body else []
                    if isinstance(merged, list):
                        merged.extend(denials)
                    else:
                        merged = [merged, *denials]
                    body = json.dumps(merged).encode("utf-8")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

            self.relay(reply, body)

        def do_GET(self) -> None:
            """The server-to-client stream. Relayed, and watched."""
            request = urllib.request.Request(proxy.upstream, method="GET")
            for key, value in dict(self.headers).items():
                if key.lower() in FORWARD_TO_SERVER and value:
                    request.add_header(key, value)
            try:
                with urllib.request.urlopen(request, timeout=proxy.timeout) as response:
                    reply = UpstreamReply(
                        response.status, list(response.headers.items()), response.read()
                    )
            except urllib.error.HTTPError as exc:
                reply = UpstreamReply(exc.code, list(exc.headers.items()), exc.read())
            except (urllib.error.URLError, TimeoutError) as exc:
                self.refuse(502, f"cannot reach the server: {exc}")
                return

            body = (
                proxy.inspect_event_stream(reply.body, {})
                if reply.is_event_stream
                else reply.body
            )
            self.relay(reply, body)

        def do_DELETE(self) -> None:
            """Session teardown. The client's business, relayed as-is."""
            request = urllib.request.Request(proxy.upstream, method="DELETE")
            for key, value in dict(self.headers).items():
                if key.lower() in FORWARD_TO_SERVER and value:
                    request.add_header(key, value)
            try:
                with urllib.request.urlopen(request, timeout=proxy.timeout) as response:
                    reply = UpstreamReply(
                        response.status, list(response.headers.items()), response.read()
                    )
            except urllib.error.HTTPError as exc:
                reply = UpstreamReply(exc.code, list(exc.headers.items()), exc.read())
            except (urllib.error.URLError, TimeoutError) as exc:
                self.refuse(502, f"cannot reach the server: {exc}")
                return
            self.relay(reply, reply.body)

    return Handler


def serve(
    upstream: str,
    name: str,
    host: str = "127.0.0.1",
    port: int = 8722,
    discover: bool = False,
    policy_path: str = "policy.yaml",
    data: Path | None = None,
) -> ThreadingHTTPServer:
    """
    Start Warden in front of an HTTP MCP server.

    `data` overrides where the registry and audit log live. Tests pass a
    temporary directory so a test run never writes into the registry a real
    user depends on.
    """
    if data is not None:
        data.mkdir(parents=True, exist_ok=True)
        reg, aud = data / "warden_registry.db", data / "warden_audit.db"
    else:
        ensure_data_dir()
        reg, aud = registry_db(), audit_db()

    enforcer = Enforcer(
        ContractRegistry(reg),
        load_policy(policy_path),
        AuditLog(aud),
        session="http",
    )
    guard = MessageGuard(enforcer, name, discover=discover, log=log)
    proxy = WardenHTTPProxy(upstream, guard)

    httpd = ThreadingHTTPServer((host, port), make_handler(proxy))
    httpd.warden_proxy = proxy  # type: ignore[attr-defined]
    return httpd


def main() -> None:
    parser = argparse.ArgumentParser(description="Warden, in front of an HTTP MCP server")
    parser.add_argument("--upstream", required=True, help="the MCP server's URL")
    parser.add_argument("--name", required=True, help="name for the registry")
    parser.add_argument("--host", default="127.0.0.1",
                        help="interface to bind, loopback by default")
    parser.add_argument("--port", type=int, default=8722)
    parser.add_argument("--discover", action="store_true",
                        help="pin whatever the server advertises, first run only")
    parser.add_argument("--policy", default="policy.yaml")
    args = parser.parse_args()

    httpd = serve(args.upstream, args.name, args.host, args.port,
                  discover=args.discover, policy_path=args.policy)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        log(f"WARNING: bound to {args.host}, which may be reachable from the network")

    log(f"listening on http://{args.host}:{args.port} -> {args.upstream}")
    log("point your MCP client at Warden's address instead of the server's")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("stopping")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
