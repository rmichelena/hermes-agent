"""Buzz kind:24200 observer-telemetry publisher for the Hermes native adapter.

Publishes agent-observer activity frames (turn_started / turn_liveness /
turn_completed / harness_started) as ephemeral kind:24200 Nostr events,
NIP-44 v2 encrypted to the agent owner (the p-tag recipient), over a
dedicated relay WebSocket with NIP-42 + NIP-OA auth (fast-path owner check).

Design constraints (Fase 1, reviewed with buzz-sysop):
- Best-effort: telemetry never breaks dispatch. Public methods never raise;
  the publisher runs on its own task and socket, failures only log (debug).
- Pacer: at most one 24200 publish per second (buzz-acp OBSERVER_PUBLISH_TICK
  parity; relay rate limit is 100/s per agent).
- Freshness: relay rejects frames older than ±5 min — stale queued events are
  dropped at dequeue time (240 s cap).
- Owner hex comes ONLY from the NIP-OA auth tag (BUZZ_AUTH_TAG element [1]),
  never from a hand-typed constant (a one-hex-char typo cost a debug round;
  the relay gate compares the p-tag owner against users.agent_owner_pubkey).
- Crypto: NIP-44 v2 port validated 101/101 against paulmillr/nip44 official
  vectors (conversation keys, message keys, padding, encrypt/decrypt).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib.util
import itertools
import json
import logging
import math
import secrets
import sys
import time
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

OBSERVER_KIND = 24200
_LIVENESS_DROP_AFTER_S = 240  # relay freshness is ±5 min; drop older
_PUBLISH_MIN_INTERVAL_S = 1.0  # pacer parity with buzz-acp
_RECONNECT_BACKOFF_MAX_S = 30.0
_QUEUE_MAX = 200
_PRESENCE_HEARTBEAT_S = 60.0  # relay presence TTL is 180s; 60s = buzz-acp parity


def _load_nostr_auth():
    """Dependency-free signing helpers from the bundled Buzz plugin."""
    path = "/opt/hermes/plugins/platforms/buzz/nostr_auth.py"
    for name, mod in list(sys.modules.items()):
        if getattr(mod, "__file__", None) == path and hasattr(mod, "schnorr_sign"):
            return mod
    spec = importlib.util.spec_from_file_location("hermes_buzz_bundled_nostr_auth", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_na = _load_nostr_auth()
public_key_hex = _na.public_key_hex
schnorr_sign = _na.schnorr_sign
build_auth_event = _na.build_auth_event
parse_auth_tag = _na.parse_auth_tag

# ── NIP-44 v2 (validated against paulmillr/nip44 vectors) ────────────────────

_FIELD_P = 2**256 - 2**32 - 977


def _lift_x(pub_hex: str) -> tuple[int, int]:
    """x-only pubkey -> (x, y_even) — the '02'+pubkey convention."""
    x = int(pub_hex[:64], 16)
    y_sq = (pow(x, 3, _FIELD_P) + 7) % _FIELD_P
    y = pow(y_sq, (_FIELD_P + 1) // 4, _FIELD_P)
    if (y * y - y_sq) % _FIELD_P != 0:
        raise ValueError("pubkey x not on curve")
    if y % 2:
        y = _FIELD_P - y
    return x, y


def _shared_x(priv: str, other_pub_hex: str) -> bytes:
    priv_int = _na.decode_private_key(priv)
    qx, qy = _lift_x(other_pub_hex)
    sx, _sy = _na._point_multiply(priv_int, (qx, qy))
    return sx.to_bytes(32, "big")


def get_conversation_key(priv: str, other_pub_hex: str) -> bytes:
    return hmac.new(b"nip44-v2", _shared_x(priv, other_pub_hex), hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _calc_padded_len(n: int) -> int:
    if n <= 32:
        return 32
    next_power = 1 << (int(math.floor(math.log2(n - 1))) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (((n - 1) // chunk) + 1)


def _get_message_keys(conversation_key: bytes, nonce: bytes):
    okm = _hkdf_expand(conversation_key, nonce, 76)
    return okm[:32], okm[32:44], okm[44:76]


def _chacha(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    enc = Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + nonce12), mode=None).encryptor()
    return enc.update(data) + enc.finalize()


def nip44_encrypt(plaintext: str, conversation_key: bytes, nonce: bytes = None) -> str:
    nonce = nonce or secrets.token_bytes(32)
    ck, cn, mk = _get_message_keys(conversation_key, nonce)
    raw = plaintext.encode()
    padded = len(raw).to_bytes(2, "big") + raw + b"\x00" * (_calc_padded_len(len(raw)) - len(raw))
    ct = _chacha(ck, cn, padded)
    mac = hmac.new(mk, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ct + mac).decode()


def nip44_decrypt(payload: str, conversation_key: bytes) -> str:
    """Inverse of :func:`nip44_encrypt` — validates the version byte and MAC
    before decrypting (needed to read owner→agent control frames)."""
    raw = base64.b64decode(payload)
    if not raw or raw[0] != 2:
        raise ValueError(f"unknown encryption version {raw[0] if raw else 'empty'}")
    nonce, ct, mac = raw[1:33], raw[33:-32], raw[-32:]
    ck, cn, mk = _get_message_keys(conversation_key, nonce)
    expect = hmac.new(mk, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        raise ValueError("invalid MAC")
    padded = _chacha(ck, cn, ct)
    n = int.from_bytes(padded[:2], "big")
    out = padded[2:2 + n]
    if not 1 <= n <= 65535 or len(out) != n or len(padded) != 2 + _calc_padded_len(n):
        raise ValueError("invalid padding")
    return out.decode()


# ── Publisher ────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _ws_url(relay_url: str) -> str:
    url = (relay_url or "").strip()
    if url.startswith("ws://") or url.startswith("wss://"):
        return url
    if url.startswith("http://"):
        return "ws://" + url[len("http://"):]
    if url.startswith("https://"):
        return "wss://" + url[len("https://"):]
    return "wss://" + url


class ObserverPublisher:
    """Owns the 24200 socket, queue, pacer and event signing."""

    def __init__(self, *, private_key: str, auth_tag_json: str, relay_url: str,
                 session_id: Optional[str] = None):
        self._auth_tag_json = auth_tag_json
        tag = parse_auth_tag(auth_tag_json, "BUZZ_AUTH_TAG")
        self.owner = str(tag[1]).lower()
        if len(self.owner) != 64 or any(c not in "0123456789abcdef" for c in self.owner):
            raise ValueError("auth tag owner pubkey is not 64-hex")
        self.priv = private_key
        self.agent_pub = public_key_hex(private_key)
        self.conversation_key = get_conversation_key(private_key, self.owner)
        self.ws_url = _ws_url(relay_url)
        self.session_id = session_id or f"hermes-{uuid.uuid4().hex[:12]}"
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._seq = itertools.count(1)
        self._task: Optional[asyncio.Task] = None
        self._stopping = False
        self.published_frames = 0

    # ── public API (never raises) ──────────────────────────────────────────

    def emit(self, kind: str, *, channel_id: Optional[str] = None,
             turn_id: Optional[str] = None, started_at: Optional[str] = None,
             payload: Optional[dict] = None) -> None:
        try:
            event = self._observer_event(
                kind, channel_id=channel_id, turn_id=turn_id,
                started_at=started_at, payload=payload)
            event["_enqueued_at"] = time.time()
            self._queue.put_nowait(("telemetry", event))
        except Exception:
            logger.debug("Buzz observer: emit(%s) failed", kind, exc_info=True)

    def emit_typing(self, channel_id: str, thread_root: Optional[str] = None) -> None:
        """Enqueue a kind:20002 typing indicator (buzz-acp parity: empty
        content, ``h`` channel tag, NIP-10 ``e`` root tag when threaded)."""
        try:
            tags: list = [["h", channel_id]]
            if thread_root:
                tags.append(["e", thread_root, "", "root"])
            self._queue.put_nowait(("typing", tags))
        except Exception:
            logger.debug("Buzz observer: emit_typing failed", exc_info=True)

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping = False
            self._task = asyncio.create_task(self._run())

    async def flush(self, timeout_s: float = 1.5) -> None:
        """Bounded wait for the publish queue to drain (shutdown path)."""
        deadline = time.monotonic() + timeout_s
        while not self._queue.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

    async def stop(self, grace_s: float = 2.0) -> None:
        self._stopping = True
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=grace_s)
        except BaseException:  # noqa: BLE001 — teardown must never raise
            pass

    # ── internals ──────────────────────────────────────────────────────────

    def _observer_event(self, kind: str, *, channel_id: Optional[str] = None,
                        turn_id: Optional[str] = None,
                        started_at: Optional[str] = None,
                        payload: Optional[dict] = None) -> dict:
        return {
            "seq": next(self._seq), "timestamp": _now_iso(), "kind": kind,
            "agentIndex": 0, "channelId": channel_id or "",
            "sessionId": self.session_id,
            "turnId": turn_id or str(uuid.uuid4()),
            "startedAt": started_at or _now_iso(), "payload": payload or {},
        }

    def _build_event(self, plaintext_events: list[dict]) -> dict:
        if len(plaintext_events) == 1:
            plain = {k: v for k, v in plaintext_events[0].items() if k != "_enqueued_at"}
        else:
            first = plaintext_events[0]
            plain = {k: v for k, v in first.items() if k != "_enqueued_at"}
            plain["kind"] = "batch"
            plain["payload"] = {"events": [
                {k: v for k, v in e.items() if k != "_enqueued_at"}
                for e in plaintext_events]}
        content = nip44_encrypt(
            json.dumps(plain, separators=(",", ":"), ensure_ascii=False),
            self.conversation_key)
        tags = [["p", self.owner], ["agent", self.agent_pub], ["frame", "telemetry"]]
        ts = int(time.time())
        ser = json.dumps([0, self.agent_pub, ts, OBSERVER_KIND, tags, content],
                         separators=(",", ":"), ensure_ascii=False).encode()
        eid = hashlib.sha256(ser).hexdigest()
        return {"id": eid, "pubkey": self.agent_pub, "created_at": ts,
                "kind": OBSERVER_KIND, "tags": tags, "content": content,
                "sig": schnorr_sign(bytes.fromhex(eid), self.priv).hex()}

    async def _auth_ws(self, ws) -> None:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=20))
        if not (isinstance(msg, list) and msg[0] == "AUTH"):
            raise ConnectionError(f"expected NIP-42 challenge, got {str(msg)[:80]}")
        ev = build_auth_event(private_key=self.priv, challenge=str(msg[1]),
                              relay_url=self.ws_url,
                              auth_tag_json=self._auth_tag_json)
        await ws.send(json.dumps(["AUTH", ev], separators=(",", ":")))
        while True:
            r = json.loads(await asyncio.wait_for(ws.recv(), timeout=20))
            if r[0] == "OK" and r[1] == ev["id"]:
                if r[2] is not True:
                    raise ConnectionError(f"WS AUTH rejected: {r[3]}")
                return

    def _build_typing_event(self, tags: list) -> dict:
        ts = int(time.time())
        ser = json.dumps([0, self.agent_pub, ts, 20002, tags, ""],
                         separators=(",", ":"), ensure_ascii=False).encode()
        eid = hashlib.sha256(ser).hexdigest()
        return {"id": eid, "pubkey": self.agent_pub, "created_at": ts,
                "kind": 20002, "tags": tags, "content": "",
                "sig": schnorr_sign(bytes.fromhex(eid), self.priv).hex()}

    def _build_presence_event(self, status: str) -> dict:
        """kind:20001 — content is the literal status string, tag ["status", …]
        (buzz-sdk build_presence_update / buzz-acp both accepted by the relay)."""
        tags = [["status", status]]
        ts = int(time.time())
        ser = json.dumps([0, self.agent_pub, ts, 20001, tags, status],
                         separators=(",", ":"), ensure_ascii=False).encode()
        eid = hashlib.sha256(ser).hexdigest()
        return {"id": eid, "pubkey": self.agent_pub, "created_at": ts,
                "kind": 20001, "tags": tags, "content": status,
                "sig": schnorr_sign(bytes.fromhex(eid), self.priv).hex()}

    async def publish_presence_standalone(self, status: str,
                                          budget_s: float = 3.5) -> bool:
        """One presence event over a short-lived dedicated WS. Used on
        shutdown (offline): no subprocess, no shared-socket races with the
        publisher loop, bounded well under the adapter disconnect budget
        (gateway default 5s; on overrun the shutdown wrapper detaches)."""
        try:
            import websockets
            async with websockets.connect(self.ws_url, max_size=2_000_000,
                                          open_timeout=budget_s) as ws:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=budget_s))
                if not (isinstance(msg, list) and msg[0] == "AUTH"):
                    return False
                ev = build_auth_event(private_key=self.priv, challenge=str(msg[1]),
                                      relay_url=self.ws_url,
                                      auth_tag_json=self._auth_tag_json)
                await ws.send(json.dumps(["AUTH", ev], separators=(",", ":")))
                event = self._build_presence_event(status)
                await ws.send(json.dumps(["EVENT", event], separators=(",", ":")))
                while True:
                    r = json.loads(await asyncio.wait_for(ws.recv(), timeout=budget_s))
                    if r[0] == "OK" and r[1] == event["id"]:
                        return r[2] is True
        except Exception:
            logger.debug("Buzz observer: standalone presence publish failed",
                         exc_info=True)
            return False

    async def _publish(self, ws, events) -> None:
        if isinstance(events, tuple):
            item_type, item = events
            if item_type == "typing":
                event = self._build_typing_event(item)
            elif item_type == "presence":
                event = self._build_presence_event(item)
            else:
                event = self._build_event(item)
        else:
            event = self._build_event(events)
        await ws.send(json.dumps(["EVENT", event], separators=(",", ":")))
        while True:
            r = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
            if r[0] == "OK" and r[1] == event["id"]:
                if r[2] is not True:
                    raise RuntimeError(f"observer frame rejected: {r[3]}")
                self.published_frames += 1
                return

    async def _run(self) -> None:
        import websockets
        backoff = 1.0
        harness_announced = False
        while not self._stopping:
            try:
                async with websockets.connect(self.ws_url, max_size=2_000_000) as ws:
                    await self._auth_ws(ws)
                    if not harness_announced:
                        harness_announced = True
                        await self._publish(ws, [self._observer_event(
                            "harness_started",
                            payload={"adapter": "hermes-native-observer",
                                     "telemetry": "kind:24200"})])
                        await self._publish(ws, ("presence", "online"))
                        backoff = 1.0
                    last_presence = time.time()
                    while not self._stopping:
                        try:
                            item_type, first = await asyncio.wait_for(
                                self._queue.get(), timeout=_PRESENCE_HEARTBEAT_S / 2)
                        except asyncio.TimeoutError:
                            if time.time() - last_presence >= _PRESENCE_HEARTBEAT_S:
                                last_presence = time.time()
                                await self._publish(ws, ("presence", "online"))
                            continue
                        if item_type == "typing":
                            # Latency-sensitive: publish solo, no batching.
                            await self._publish(ws, ("typing", first))
                            backoff = 1.0
                            await asyncio.sleep(_PUBLISH_MIN_INTERVAL_S)
                            continue
                        now = time.time()
                        if now - first.get("_enqueued_at", now) > _LIVENESS_DROP_AFTER_S:
                            continue  # stale — relay freshness is ±5 min
                        batch = [first]
                        while len(batch) < 8 and not self._queue.empty():
                            nxt_type, nxt = self._queue.get_nowait()
                            if nxt_type == "typing":
                                # Publish pending typing first, then resume.
                                await self._publish(ws, ("typing", nxt))
                                continue
                            if now - nxt.get("_enqueued_at", now) <= _LIVENESS_DROP_AFTER_S:
                                batch.append(nxt)
                        await self._publish(ws, batch)
                        backoff = 1.0
                        await asyncio.sleep(_PUBLISH_MIN_INTERVAL_S)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Buzz observer: publisher reconnect (%s)", exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX_S)
