"""SecretSpec external provider endpoint (`secretspec.provider/1`, IPC v1).

Speaks the SecretSpec Secret Provider Protocol (0.21+) over NDJSON on
stdio, so `secretspec get/run/check` can resolve secrets straight out of a
running KeepassXC, with every unlock gated by a Yubikey touch.

Security model: unchanged from the CLI. The sealing key is derived from a
Yubikey challenge-response on EVERY fetch -- nothing caches the response or
the derived key, across requests, batches, or the process lifetime. The
touch IS the security boundary; the endpoint simply consumes its request
deadline while waiting for it.

Registration (user claim, no PATH discovery needed):

    ~/.config/secretspec/providers.d/kpget.secretspec.json
    {"executable": "<abs path to kpget-secretspec-provider>",
     "environment": ["KPGET_*"]}

KPGET_DB and KPGET_YKMAN keep working; the claim authorizes their
passthrough into the endpoint's otherwise fixed environment.
"""
from __future__ import annotations

import base64
import json
import os
import shlex
import subprocess
import sys
import threading
import time

from . import crypto, store, yubikey

PROTOCOL = "secretspec.provider"
PROTOCOL_VERSION = 1
SCHEME = "kpget"
SERVER_NAME = "kpget-secretspec-provider"
ABS_MAX_FRAME_BYTES = 1_048_576
MAX_IN_FLIGHT = 1
MAX_DEPTH = 64
DEADLINE_HORIZON_MS = 300_000  # receiver-side clamp from the wire spec

METHODS = [
    "provider.resolve_address",
    "provider.get",
    "provider.get_many",
    "provider.exists",
]

PROVIDER_METADATA = {
    "name": SCHEME,
    "display_uri": "kpget://",
    "supported_coordinates": ["field"],
    "generated_value_persistence": "persist",
    "prompted_value_persistence": "persist",
    "storage_identity": "kpget://",
    "entry_container_identity": "kpget://",
    "physical_store_path": None,
}

# SecretSpec-reserved server error codes (ipc-wire reference).
CODES = {
    "unsupported_version": -32000,
    "capability_required": -32001,
    "deadline_exceeded": -32002,
    "cancelled": -32003,
    "unavailable": -32004,
    "permission_denied": -32005,
    "interaction_required": -32006,
    "conflict": -32007,
    "operation_failed": -32008,
    "message_too_large": -32009,
    "invalid_request": -32600,
    "invalid_params": -32602,
}


class ProtocolError(Exception):
    """Maps to a JSON-RPC error object; message must be secret-free."""

    def __init__(self, kind: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.retryable = retryable

    def to_jsonrpc(self) -> dict:
        return {
            "code": CODES[self.kind],
            "message": self.message,
            "data": {"kind": self.kind, "retryable": self.retryable},
        }


def _unavailable(msg: str) -> ProtocolError:
    return ProtocolError("unavailable", msg, retryable=True)


# ---------------------------------------------------------------- wire I/O

class _FrameTooLarge(Exception):
    pass


def _reject_dup_keys(pairs):
    seen = set()
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate object key")
        seen.add(key)
    return dict(pairs)


def _check_depth(node, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("JSON nesting too deep")
    if isinstance(node, dict):
        for value in node.values():
            _check_depth(value, depth + 1)
    elif isinstance(node, list):
        for value in node:
            _check_depth(value, depth + 1)


def read_frame(stream) -> dict:
    line = stream.readline(ABS_MAX_FRAME_BYTES + 2)
    if not line:
        raise EOFError
    if b"\r" in line:
        raise ValueError("CR in frame")
    if not line.endswith(b"\n"):
        raise _FrameTooLarge
    line = line[:-1]
    if not line:
        raise ValueError("empty frame")
    if len(line) > ABS_MAX_FRAME_BYTES:
        raise _FrameTooLarge
    try:
        message = json.loads(line.decode("utf-8"), object_pairs_hook=_reject_dup_keys)
        _check_depth(message)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("malformed frame") from None
    if not isinstance(message, dict):
        raise ValueError("frame is not a JSON object")
    return message


class Writer:
    def __init__(self, stream):
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, message: dict, max_frame_bytes: int) -> None:
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with self._lock:
            if len(payload) > max_frame_bytes:
                raise _FrameTooLarge
            self._stream.write(payload + b"\n")
            self._stream.flush()


# ---------------------------------------------------------------- session

class Session:
    """Connection state for one provider URI session."""

    def __init__(self, writer: Writer):
        self.writer = writer
        self.ready = False
        self.draining = False
        self.last_inbound_id = 0
        self.max_frame_bytes = ABS_MAX_FRAME_BYTES
        self.inflight = 0
        self.inflight_lock = threading.Lock()
        self.cancel_events: dict[int, threading.Event] = {}

    def begin_request(self, request_id: int) -> threading.Event:
        """Registers the in-flight request and returns its cancel event."""
        with self.inflight_lock:
            if self.inflight >= MAX_IN_FLIGHT:
                raise _unavailable("another operation is in flight")
            self.inflight += 1
            event = threading.Event()
            self.cancel_events[request_id] = event
            return event

    def end_request(self, request_id: int | None) -> None:
        with self.inflight_lock:
            self.inflight -= 1
        if request_id is not None:
            with self.inflight_lock:
                self.cancel_events.pop(request_id, None)



def _request_id_ok(session: Session, request_id) -> bool:
    return (
        isinstance(request_id, int)
        and not isinstance(request_id, bool)
        and 1 <= request_id <= 9_007_199_254_740_991
        and request_id > session.last_inbound_id
    )


def _deadline_from_meta(meta) -> float:
    """Returns a monotonic deadline; raises if _meta is malformed."""
    if not isinstance(meta, dict):
        raise ProtocolError("invalid_params", "_meta must be an object")
    unknown = set(meta) - {"deadline_unix_ms", "parent_request_id"}
    if unknown:
        raise ProtocolError("invalid_params", "unknown _meta member")
    deadline = meta.get("deadline_unix_ms")
    if not isinstance(deadline, int) or isinstance(deadline, bool) or deadline < 0:
        raise ProtocolError("invalid_params", "deadline_unix_ms must be an unsigned integer")
    now_ms = time.time() * 1000
    if deadline <= now_ms:
        raise ProtocolError("deadline_exceeded", "request deadline already elapsed")
    remaining_ms = min(deadline - now_ms, DEADLINE_HORIZON_MS)
    return time.monotonic() + remaining_ms / 1000


def _require_object(params, allowed: set, what: str) -> dict:
    if not isinstance(params, dict):
        raise ProtocolError("invalid_params", f"{what} must be an object")
    unknown = set(params) - allowed
    if unknown:
        raise ProtocolError("invalid_params", f"unknown member in {what}")
    return params


def _validate_address(params: dict) -> dict:
    address = params.get("address")
    if not isinstance(address, dict):
        raise ProtocolError("invalid_params", "address must be an object")
    kind = address.get("kind")
    if kind == "convention":
        extra = set(address) - {"kind", "project", "profile", "key"}
        if extra:
            raise ProtocolError("invalid_params", "unknown member in convention address")
        for member in ("project", "profile", "key"):
            value = address.get(member)
            if not isinstance(value, str) or not value:
                raise ProtocolError("invalid_params", f"convention address {member} must be a non-empty string")
            if len(value.encode()) > 4096:
                raise ProtocolError("invalid_params", "address component exceeds 4096 bytes")
        return {"kind": "convention", "project": address["project"],
                "profile": address["profile"], "key": address["key"]}
    if kind == "native":
        extra = set(address) - {"kind", "coordinates"}
        if extra:
            raise ProtocolError("invalid_params", "unknown member in native address")
        coords = address.get("coordinates")
        if not isinstance(coords, dict):
            raise ProtocolError("invalid_params", "native address requires coordinates")
        unknown = set(coords) - {"item", "field", "vault", "section", "version"}
        if unknown:
            raise ProtocolError("invalid_params", "unsupported native coordinate")
        item = coords.get("item")
        if not isinstance(item, str) or not item:
            raise ProtocolError("invalid_params", "native coordinate item must be a non-empty string")
        if len(item.encode()) > 4096:
            raise ProtocolError("invalid_params", "address component exceeds 4096 bytes")
        field = coords.get("field")
        if field is not None and not isinstance(field, str):
            raise ProtocolError("invalid_params", "field must be a string or null")
        if field is not None and field not in ("password", "username", "totp"):
            raise ProtocolError("invalid_params", "unsupported field coordinate")
        normalized = {
            "item": item,
            "field": field,
            "vault": coords.get("vault"),
            "section": coords.get("section"),
            "version": coords.get("version"),
        }
        for coordinate, value in normalized.items():
            if isinstance(value, str) and len(value.encode()) > 4096:
                raise ProtocolError("invalid_params", "address component exceeds 4096 bytes")
        return {"kind": "native", "coordinates": normalized}
    raise ProtocolError("invalid_params", "address kind must be convention or native")


def _coordinates_of(address: dict) -> dict:
    if address["kind"] == "native":
        return address["coordinates"]
    # Convention namespace: the logical key is the search item. Declarations
    # should use refs (item = the KeepassXC entry URL) for precise targeting.
    return {"item": address["key"], "field": None, "vault": None, "section": None, "version": None}


# ---------------------------------------------------------------- backend

def _challenge_response(deadline: float, cancelled: threading.Event) -> bytes:
    """Yubikey challenge-response, pollable so cancel/deadline stay live.

    Blocks until the physical touch. Nothing here is cached -- every call
    mints exactly one sealing-key input.
    """
    cmd = shlex.split(os.environ.get("KPGET_YKMAN") or "sudo ykman")
    argv = [*cmd, "otp", "calculate", "1", yubikey.DEFAULT_CHALLENGE]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError:
        raise _unavailable("ykman could not be started") from None
    try:
        while True:
            if cancelled.is_set():
                proc.kill()
                raise ProtocolError("cancelled", "operation cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                raise ProtocolError("deadline_exceeded", "touch deadline elapsed")
            try:
                stdout, stderr = proc.communicate(timeout=min(0.25, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if proc.poll() is None:
            proc.kill()
    if proc.returncode != 0:
        text = (stderr or "") + (stdout or "")
        if "no yubikey" in text.lower():
            # Protocol stderr may not carry addresses or secret names; keep
            # the note generic and let the host render provider guidance.
            print(
                "kpget-secretspec-provider: no Yubikey detected; plug it in,"
                " or copy the secret from KeepassXC manually",
                file=sys.stderr,
            )
            raise ProtocolError("interaction_required", "yubikey not detected")
        raise _unavailable("yubikey unavailable or not touched in time")
    try:
        return yubikey.parse_response(stdout)
    except yubikey.YubikeyError:
        raise _unavailable("yubikey returned an unexpected response") from None


def _active_hash() -> str:
    probe = _connect()
    try:
        return probe.get_databasehash()
    finally:
        try:
            probe.disconnect()
        except Exception:
            pass


def _connect():
    from keepassxc_proxy_client import protocol

    session = protocol.Connection()
    try:
        session.connect()
    except OSError:
        raise _unavailable("KeepassXC browser socket unreachable") from None
    return session


def _entries_for(item: str, deadline: float, cancelled: threading.Event):
    """One Yubikey touch, then the matching KeepassXC login entries."""
    conn = store.connect()
    rows = store.rows(conn)
    if not rows:
        raise ProtocolError("operation_failed", "no registered associations; run kpget register")
    active_hash = _active_hash()
    sealing = crypto.derive_key(_challenge_response(deadline, cancelled))
    errors: list[str] = []
    candidates = 0
    for row in rows:
        if row.database_hash and row.database_hash != active_hash:
            continue
        candidates += 1
        try:
            # register seals base64(public_key); load_associate wants raw bytes.
            public_key = base64.b64decode(crypto.unseal(sealing, row.sealed))
        except crypto.SealError:
            errors.append("unseal failed")
            continue
        session = _connect()
        try:
            session.load_associate(row.name, public_key)
            session.test_associate()
        except Exception:
            errors.append("association rejected")
            close_quietly(session)
            continue
        try:
            entries = session.get_logins(item)
        except Exception:
            errors.append("query failed")
            close_quietly(session)
            continue
        close_quietly(session)
        if entries:
            return entries
        return []
    if errors:
        raise ProtocolError(
            "operation_failed",
            "association rejected by KeepassXC; if the focused database "
            "changed, run kpget register with it focused")
    if candidates == 0:
        raise ProtocolError(
            "operation_failed",
            "no association for the active database; run kpget register "
            "with it focused")
    return []


def close_quietly(session) -> None:
    try:
        session.disconnect()
    except Exception:
        pass


FIELD_KEYS = {"password": ("password", "loginPassword"),
              "username": ("login", "loginName"),
              "totp": ("totp",)}


def _extract(entries: list, field: str | None) -> str | None:
    keys = FIELD_KEYS[field or "password"]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in keys:
            value = entry.get(key)
            if isinstance(value, str) and value:
                return value
    return None


# ---------------------------------------------------------------- handlers

def resolve_address(params: dict, deadline: float, cancelled: threading.Event) -> dict:
    _require_object(params, {"address"}, "params")
    address = _validate_address(params)
    coords = _coordinates_of(address)
    return {"coordinates": {k: coords.get(k) for k in ("item", "field", "vault", "section", "version")}}


def provider_get(params: dict, deadline: float, cancelled: threading.Event) -> dict:
    _require_object(params, {"address"}, "params")
    address = _validate_address(params)
    coords = _coordinates_of(address)
    entries = _entries_for(coords["item"], deadline, cancelled)
    value = _extract(entries, coords.get("field"))
    if value is None:
        return {"status": "missing"}
    return {"status": "found", "value": value, "expires_at_unix_ms": None}


def provider_get_many(params: dict, deadline: float, cancelled: threading.Event) -> dict:
    _require_object(params, {"requests"}, "params")
    requests = params.get("requests")
    if not isinstance(requests, list) or not requests or len(requests) > 1024:
        raise ProtocolError("invalid_params", "requests must be a non-empty array of at most 1024 items")
    results = []
    seen_names = set()
    for request in requests:
        if not isinstance(request, dict):
            raise ProtocolError("invalid_params", "each request must be an object")
        name = request.get("name")
        if not isinstance(name, str) or not name or name in seen_names:
            raise ProtocolError("invalid_params", "request names must be unique non-empty strings")
        seen_names.add(name)
        address = _validate_address(request)
        coords = _coordinates_of(address)
        try:
            entries = _entries_for(coords["item"], deadline, cancelled)
            value = _extract(entries, coords.get("field"))
        except ProtocolError:
            raise  # version 1 has no partial per-item errors: the batch fails
        if value is None:
            results.append({"name": name, "status": "missing"})
        else:
            results.append({"name": name, "status": "found", "value": value, "expires_at_unix_ms": None})
    return {"results": results}


def provider_exists(params: dict, deadline: float, cancelled: threading.Event) -> dict:
    _require_object(params, {"address"}, "params")
    address = _validate_address(params)
    coords = _coordinates_of(address)
    entries = _entries_for(coords["item"], deadline, cancelled)
    return {"exists": bool(entries)}


HANDLERS = {
    "provider.resolve_address": resolve_address,
    "provider.get": provider_get,
    "provider.get_many": provider_get_many,
    "provider.exists": provider_exists,
}


# ---------------------------------------------------------------- openrpc

def openrpc_document() -> dict:
    address_schema = {
        "oneOf": [
            {"type": "object", "properties": {
                "kind": {"const": "convention"},
                "project": {"type": "string"}, "profile": {"type": "string"}, "key": {"type": "string"}},
             "required": ["kind", "project", "profile", "key"], "additionalProperties": False},
            {"type": "object", "properties": {
                "kind": {"const": "native"},
                "coordinates": {"type": "object", "properties": {
                    "item": {"type": "string"}, "field": {"type": ["string", "null"]},
                    "vault": {"type": ["string", "null"]}, "section": {"type": ["string", "null"]},
                    "version": {"type": ["string", "null"]}},
                    "required": ["item"], "additionalProperties": False}},
             "required": ["kind", "coordinates"], "additionalProperties": False},
        ]
    }

    def method(name: str, params_schema: dict, result_schema: dict) -> dict:
        return {
            "name": name,
            "params": [{"name": "params", "required": True, "schema": params_schema}],
            "result": {"name": "result", "schema": result_schema},
        }

    return {
        "openrpc": "1.3.2",
        "info": {"title": "kpget Secret Provider Protocol", "version": "1"},
        "methods": [
            method("provider.resolve_address",
                   {"type": "object", "properties": {"address": address_schema},
                    "required": ["address"], "additionalProperties": False},
                   {"type": "object"}),
            method("provider.get",
                   {"type": "object", "properties": {"address": address_schema},
                    "required": ["address"], "additionalProperties": False},
                   {"type": "object"}),
            method("provider.get_many",
                   {"type": "object", "properties": {"requests": {"type": "array"}},
                    "required": ["requests"], "additionalProperties": False},
                   {"type": "object"}),
            method("provider.exists",
                   {"type": "object", "properties": {"address": address_schema},
                    "required": ["address"], "additionalProperties": False},
                   {"type": "object"}),
        ],
        "components": {"schemas": {"Address": address_schema}},
        "x-secretspec": {
            "protocol": PROTOCOL,
            "versions": [PROTOCOL_VERSION],
            "server": {"name": SERVER_NAME, "version": _version()},
            "methods": METHODS,
            "absolute_max_frame_bytes": ABS_MAX_FRAME_BYTES,
        },
    }


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("kpget")
    except Exception:
        return "0"


# ---------------------------------------------------------------- server

def _serve(stream_in, stream_out) -> int:
    writer = Writer(stream_out)
    session = Session(writer)

    def respond(request_id, result=None, error: ProtocolError | None = None):
        message = {"jsonrpc": "2.0", "id": request_id}
        if error is not None:
            message["error"] = error.to_jsonrpc()
        else:
            message["result"] = result
        try:
            writer.write(message, session.max_frame_bytes)
        except _FrameTooLarge:
            writer.write({"jsonrpc": "2.0", "id": request_id,
                          "error": ProtocolError("message_too_large", "result exceeds frame limit").to_jsonrpc()},
                         ABS_MAX_FRAME_BYTES)

    def run_worker(session: Session, request_id, handler, params: dict,
                   deadline: float, cancelled: threading.Event):
        try:
            result = handler(params, deadline, cancelled)
            respond(request_id, result=result)
        except ProtocolError as exc:
            respond(request_id, error=exc)
        except Exception:
            respond(request_id, error=ProtocolError("operation_failed", "operation failed"))
        finally:
            session.end_request(request_id)

    while True:
        try:
            frame = read_frame(stream_in)
        except EOFError:
            return 0
        except (ValueError, _FrameTooLarge):
            return 2  # transport-fatal: malformed or oversize frame

        jsonrpc = frame.get("jsonrpc")
        method = frame.get("method")
        has_id = "id" in frame
        request_id = frame.get("id")
        if method is None and ("result" in frame or "error" in frame):
            # A response naming no callback this endpoint raised: no response
            # channel exists for it, so the connection closes immediately.
            return 0  # immediate close is the specified handling, not a crash
        unknown_top = set(frame) - {"jsonrpc", "method", "params", "id", "_meta"}
        if jsonrpc != "2.0" or not isinstance(method, str) or unknown_top:
            if has_id:
                respond(None, error=ProtocolError("invalid_request", "malformed request envelope"))
            elif jsonrpc == "2.0" and isinstance(method, str) and unknown_top:
                # Notification with an unknown envelope member: rejected,
                # then the connection closes.
                respond(None, error=ProtocolError("invalid_request", "unknown notification member"))
                return 0
            continue
        if not has_id:
            extra = set(frame) - {"jsonrpc", "method", "params"}
            if extra:
                respond(None, error=ProtocolError("invalid_request", "unknown notification member"))
                return 0
            if not isinstance(frame.get("params", {}), dict):
                continue
            if method == "rpc.cancel":
                target = frame.get("params", {}).get("id")
                with session.inflight_lock:
                    event = session.cancel_events.get(target) if isinstance(target, int) else None
                    if event is not None:
                        event.set()
            continue  # unknown notifications are ignored

        # Requests. Before readiness, the only legal requests are discovery
        # and initialization; anything else gets one invalid_request, then
        # the connection closes -- even when the id itself is unusable.
        if not session.ready and method not in ("rpc.discover", "rpc.initialize"):
            respond(request_id if isinstance(request_id, int) and not isinstance(request_id, bool) else None,
                    error=ProtocolError("invalid_request", "not initialized"))
            return 0
        if not _request_id_ok(session, request_id):
            respond(None,
                    error=ProtocolError("invalid_request", "invalid request id"))
            continue
        session.last_inbound_id = request_id
        try:
            deadline = _deadline_from_meta(frame.get("_meta"))
        except ProtocolError as exc:
            respond(request_id, error=exc)
            continue

        if method == "rpc.cancel":
            respond(request_id, error=ProtocolError("invalid_request", "rpc.cancel is a notification"))
            continue
        if method == "rpc.shutdown":
            respond(request_id, result={})
            drain_until = time.monotonic() + 5.0
            while time.monotonic() < drain_until:
                with session.inflight_lock:
                    if session.inflight == 0:
                        break
                time.sleep(0.05)
            return 0
        if method == "rpc.discover":
            try:
                respond(request_id, result=openrpc_document())
            except _FrameTooLarge:
                pass
            continue
        if method == "rpc.initialize":
            if session.ready:
                respond(request_id, error=ProtocolError("invalid_request", "already initialized"))
                return 0
            try:
                application = _initialize(frame.get("params"), session)
            except ProtocolError as exc:
                respond(request_id, error=exc)
                return 0
            respond(request_id, result=application)
            session.ready = True
            continue

        # Application methods.
        handler = HANDLERS.get(method)
        if handler is None:
            respond(request_id, error=ProtocolError("capability_required", "method not advertised"))
            continue
        params = frame.get("params", {})
        if not isinstance(params, dict):
            respond(request_id, error=ProtocolError("invalid_params", "params must be an object"))
            continue
        try:
            event = session.begin_request(request_id)
        except ProtocolError as exc:
            respond(request_id, error=exc)
            continue
        threading.Thread(target=run_worker,
                         args=(session, request_id, handler, params, deadline, event),
                         daemon=True).start()


def _initialize(params, session: Session) -> dict:
    body = _require_object(params, {"protocol", "versions", "client", "limits",
                                    "client_methods", "application"}, "params")
    if body.get("protocol") != PROTOCOL:
        raise ProtocolError("unsupported_version", "unsupported protocol")
    versions = body.get("versions")
    if not isinstance(versions, list) or PROTOCOL_VERSION not in versions or not versions:
        raise ProtocolError("unsupported_version", "no common protocol version")
    limits = body.get("limits", {})
    if not isinstance(limits, dict):
        raise ProtocolError("invalid_params", "limits must be an object")
    requested_frame = limits.get("max_frame_bytes", ABS_MAX_FRAME_BYTES)
    if not isinstance(requested_frame, int) or not 4096 <= requested_frame <= ABS_MAX_FRAME_BYTES:
        raise ProtocolError("invalid_params", "max_frame_bytes out of range")
    requested_inflight = limits.get("max_in_flight", MAX_IN_FLIGHT)
    if not isinstance(requested_inflight, int) or not 1 <= requested_inflight <= 32:
        raise ProtocolError("invalid_params", "max_in_flight out of range")
    application = body.get("application")
    if not isinstance(application, dict):
        raise ProtocolError("invalid_params", "application must be an object")
    if application.get("scheme") != SCHEME:
        raise ProtocolError("invalid_params", "scheme mismatch")
    uri = application.get("uri")
    if not isinstance(uri, str) or not uri.startswith(f"{SCHEME}://"):
        raise ProtocolError("invalid_params", "uri scheme mismatch")
    if "context" in application and application["context"] is not None:
        context = application["context"]
        if not isinstance(context, dict):
            raise ProtocolError("invalid_params", "context must be an object or null")
        unknown = set(context) - {"project", "profile", "base_dir", "reason",
                                  "requested_authorization_duration_ms"}
        if unknown:
            raise ProtocolError("invalid_params", "unknown context member")
    return {
        "protocol": PROTOCOL,
        "version": PROTOCOL_VERSION,
        "server": {"name": SERVER_NAME, "version": _version()},
        "methods": METHODS,
        "capabilities": {},
        "limits": {"max_frame_bytes": min(requested_frame, ABS_MAX_FRAME_BYTES),
                   "max_in_flight": min(requested_inflight, MAX_IN_FLIGHT)},
        "application": {"provider": PROVIDER_METADATA},
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv != ["provider"]:
        print(f"usage: {SERVER_NAME} [provider]", file=sys.stderr)
        return 2
    from .cli import _runtime_dir

    _runtime_dir()
    try:
        return _serve(sys.stdin.buffer, sys.stdout.buffer)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
