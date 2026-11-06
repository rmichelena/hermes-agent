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
import contextlib  # r5 M4: QueueFull eviction
_queue_full = asyncio.QueueFull

OBSERVER_KIND = 24200
_LIVENESS_DROP_AFTER_S = 240  # relay freshness is ±5 min; drop older
_PUBLISH_MIN_INTERVAL_S = 1.0  # pacer parity with buzz-acp
_RECONNECT_BACKOFF_MAX_S = 30.0
_QUEUE_MAX = 200
_PRESENCE_HEARTBEAT_S = 60.0  # relay presence TTL is 180s; 60s = buzz-acp parity


def _load_nostr_auth():
    """Dependency-free signing helpers from the bundled Buzz plugin.

    Resolved relative to this file so any checkout/install root works;
    a missing sibling is a hard error for telemetry but must not be
    triggered by unrelated layouts (multireview C1).
    """
    from pathlib import Path
    path = str(Path(__file__).with_name("nostr_auth.py"))
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
    # r4: NIP-44 silently miscomputes on malformed pubkeys (wrong length, or
    # x >= curve p) — e.g. a wrong-but-hex-valid owner in BUZZ_AUTH_TAG.
    if not _valid_owner_hex(other_pub_hex):
        raise ValueError(f"invalid pubkey for NIP-44: {other_pub_hex[:16]}…")
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


def _valid_owner_hex(pub_hex: str) -> bool:
    """r4/r5: NIP-44 conversation keys silently miscompute on malformed
    pubkeys — validate against the secp256k1 field prime (r5 finding: the
    first cut used the Ed25519 prime and rejected ~half the valid Nostr
    pubkeys, those with x >= 2**255)."""
    if len(pub_hex) != 64:
        return False
    try:
        n = int(pub_hex, 16)
    except ValueError:
        return False
    if n >= _FIELD_P:
        return False
    # r7 M-3: on-curve — x debe tener raiz cuadrada y^2 = x^3+7 (mod p);
    # _lift_x ya computa el residuo: falla limpio si no esta en la curva.
    try:
        _lift_x(pub_hex)
    except Exception:
        return False
    return True


def _get_message_keys(conversation_key: bytes, nonce: bytes):
    okm = _hkdf_expand(conversation_key, nonce, 76)
    return okm[:32], okm[32:44], okm[44:76]


def _chacha(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    enc = Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + nonce12), mode=None).encryptor()
    return enc.update(data) + enc.finalize()


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


def nip44_encrypt(plaintext: str, conversation_key: bytes, nonce: bytes = None) -> str:
    nonce = nonce or secrets.token_bytes(32)
    okm = _hkdf_expand(conversation_key, nonce, 76)
    ck, cn, mk = okm[:32], okm[32:44], okm[44:76]
    raw = plaintext.encode()
    if not 1 <= len(raw) <= 65535:
        # r7: NIP-44 v2 exige 1..65535 bytes — sin guard, len 0 o >=65536
        # corrompe el padding (prefijo de 2 bytes) silenciosamente.
        raise ValueError(f"nip44: plaintext length {len(raw)} outside 1..65535")
    padded = len(raw).to_bytes(2, "big") + raw + b"\x00" * (_calc_padded_len(len(raw)) - len(raw))
    ct = _chacha(ck, cn, padded)
    mac = hmac.new(mk, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ct + mac).decode()


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
        self.published_log: list = []  # last (kind, id) published — shutdown evidence
        self._publishing = False  # True while a frame is on the wire (flush waits on it)
        self._going_offline = False  # D: heartbeat must not flip us back online at shutdown
        self._reconnects = 0
        self._stale_drops = 0  # r8 M-E

    # ── public API (never raises) ──────────────────────────────────────────

    def emit(self, kind: str, *, channel_id: Optional[str] = None,
             turn_id: Optional[str] = None, started_at: Optional[str] = None,
             payload: Optional[dict] = None, force: bool = False) -> None:
        try:
            event = self._observer_event(
                kind, channel_id=channel_id, turn_id=turn_id,
                started_at=started_at, payload=payload)
            event["_enqueued_at"] = time.time()
            try:
                self._queue.put_nowait(("telemetry", event))
            except _queue_full:
                if not force:
                    raise
                # r5 M4 + r7 M-2: shutdown cancels must not be droppable, pero
                # la eviction respeta frames precios (turn_started/harness_started):
                # solo desaloja telemetria droppable; si no hay, espera.
                _precious = ("turn_started", "harness_started")
                for _ in range(4):
                    with contextlib.suppress(Exception):
                        _, evicted = self._queue.get_nowait()
                        if not (isinstance(evicted, dict)
                                and evicted.get("kind") in _precious):
                            break  # droppable: espacio liberado
                        self._queue.put_nowait(("telemetry", evicted))  # reponer
                else:
                    # r8 M-B: cola llena de precios — dropear el mas viejo
                    # incondicionalmente: perder el cancel era peor que perder
                    # un turn_started (el completed del evictado cierra el turno).
                    with contextlib.suppress(Exception):
                        _, sacrificed = self._queue.get_nowait()
                        logger.warning(
                            "Buzz observer: queue full of precious frames — "
                            "dropped oldest %s to keep a %s", 
                            (sacrificed or {}).get("kind"), kind)
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
            # r3 M4: carry the enqueue time so the consumer's staleness drop
            # (relay freshness ±5 min) applies to typing frames too.
            self._queue.put_nowait(("typing",
                                    {"tags": tags, "_enqueued_at": time.time()}))
        except Exception:
            logger.debug("Buzz observer: emit_typing failed", exc_info=True)

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return  # idempotent: never two publishers on one adapter (L4)
        self._stopping = False
        self._task = asyncio.create_task(self._run())

    def mark_going_offline(self) -> None:
        """Suppress further ``online`` heartbeats — called before the shutdown
        offline publish so the loop cannot flip presence back (r2 finding D)."""
        self._going_offline = True

    def begin_shutdown(self) -> None:
        """Idempotent shutdown request (r3 M3): stops the loop and suppresses
        presence flips; the adapter must not poke ``_stopping`` directly."""
        self._going_offline = True
        self._stopping = True

    async def flush(self, timeout_s: float = 1.5) -> None:
        """Bounded wait for the publish queue to drain (shutdown path). The
        publisher batches up to 8 events per frame at 1 frame/s, so a couple
        of pending telemetry frames clear within the window."""
        deadline = time.monotonic() + timeout_s
        while ((not self._queue.empty()) or self._publishing) \
                and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

    async def stop(self, grace_s: float = 2.0) -> None:
        self._stopping = True
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=grace_s)
        except asyncio.CancelledError:
            # r7 M4: distinguir — si el task cancelado ya termino, es su unwind
            # esperado (tragar); si el task sigue vivo, la cancelacion es del
            # caller y NO se traga.
            if task.done():
                return
            raise
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
                                          budget_s: float = 2.8) -> bool:
        """One presence event over a short-lived dedicated WS. Used on
        shutdown (offline): no subprocess, no shared-socket races with the
        publisher loop. ``budget_s`` bounds the WHOLE operation (deadline
        math, not per-await caps) so callers can rely on it (H2)."""
        deadline = time.monotonic() + budget_s

        def _rem() -> float:
            r = deadline - time.monotonic()
            if r <= 0:
                raise asyncio.TimeoutError()
            return r

        try:
            import websockets
            async with websockets.connect(self.ws_url, max_size=2_000_000,
                                          open_timeout=min(budget_s, _rem()),
                                          close_timeout=1.0) as ws:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=_rem()))
                if not (isinstance(msg, list) and msg[0] == "AUTH"):
                    return False
                ev = build_auth_event(private_key=self.priv, challenge=str(msg[1]),
                                      relay_url=self.ws_url,
                                      auth_tag_json=self._auth_tag_json)
                await ws.send(json.dumps(["AUTH", ev], separators=(",", ":")))
                # r4: wait for the AUTH OK before EVENT — the offline signal is
                # the most visible one; an unauthenticated EVENT is rejected.
                while True:
                    r = json.loads(await asyncio.wait_for(ws.recv(), timeout=_rem()))
                    if r[0] == "OK" and r[1] == ev["id"]:
                        if r[2] is not True:
                            logger.warning("Buzz observer: standalone AUTH rejected: %s",
                                           r[3] if len(r) > 3 else "?")
                            return False
                        break
                event = self._build_presence_event(status)
                await ws.send(json.dumps(["EVENT", event], separators=(",", ":")))
                while True:
                    r = json.loads(await asyncio.wait_for(ws.recv(), timeout=_rem()))
                    if r[0] == "OK" and r[1] == event["id"]:
                        return r[2] is True
        except Exception:
            logger.debug("Buzz observer: standalone presence publish failed",
                         exc_info=True)
            return False

    async def _publish(self, ws, events) -> bool:
        # r5 H2: NIP-44 + schnorr cuestan ~86ms por frame — firmar en thread,
        # nunca en el event loop del gateway. r5 M5: _publishing en el TOPE,
        # porque flush() debe esperar tambien el tramo de firma.
        self._publishing = True
        try:
            if isinstance(events, tuple):
                item_type, item = events
                if item_type == "typing":
                    event = await asyncio.to_thread(self._build_typing_event, item)
                elif item_type == "presence":
                    if item == "online" and self._going_offline:
                        return False  # r3 M2: in-flight online must not flip the shutdown offline
                    event = await asyncio.to_thread(self._build_presence_event, item)
                else:
                    event = await asyncio.to_thread(self._build_event, item)
            else:
                event = await asyncio.to_thread(self._build_event, events)
            if (isinstance(events, tuple) and events[0] == "presence"
                    and events[1] == "online" and self._going_offline):
                return False  # r6 M-D: offline confirmado durante la firma
            await ws.send(json.dumps(["EVENT", event], separators=(",", ":")))
            while True:
                r = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
                if r[0] == "OK" and r[1] == event["id"]:
                    if r[2] is not True:
                        logger.warning("Buzz observer: frame rejected (kind=%s id=%s…): %s",
                                       event["kind"], event["id"][:12], r[3] if len(r) > 3 else "?")
                        return False
                    self.published_frames += 1
                    self.published_log.append((event["kind"], event["id"]))
                    del self.published_log[:-50]
                    return True
        finally:
            self._publishing = False


    async def _run(self) -> None:
        import websockets
        backoff = 1.0
        harness_announced = False
        while not self._stopping:
            try:
                _phase = "connect"  # r7 M-1: connect/DNS/TLS no es error de auth
                # r3 H1: assign BEFORE connect/auth — an early
                # failure (relay down at boot, DNS, TLS) must find _phase bound
                # in the except handler, or the publisher dies permanently.
                async with websockets.connect(self.ws_url, max_size=2_000_000,
                                              close_timeout=1.0) as ws:
                    # r8 M-A: "auth" SOLO para el handshake — connect/DNS/TLS ya
                    # quedo en "connect" (r7 M-1) y post-auth es "ready".
                    _phase = "auth"
                    await self._auth_ws(ws)
                    # r6 M-C: READY antes de CUALQUIER publish — un drop de
                    # transporte aca ya no se loguea como auth error.
                    _phase = "ready"
                    if not harness_announced:
                        harness_announced = await self._publish(ws, [self._observer_event(
                            "harness_started",
                            payload={"adapter": "hermes-native-observer",
                                     "telemetry": "kind:24200"})])
                    # r3-H2 verification: ready/backoff reset on EVERY successful
                    # connection — one-shot left transport drops misclassified
                    # as auth errors and drifted idle-agent backoff to 30s.
                    await self._publish(ws, ("presence", "online"))
                    backoff = 1.0
                    last_presence = time.time()
                    while not self._stopping:
                        # Presence refresh is CLOCK-driven and must NOT depend
                        # on the queue going idle: an active turn enqueues
                        # liveness every 10s, so an idle-only check never fires
                        # and the relay TTL (180s) lapses while the agent is
                        # visibly working (r2 finding A).
                        if (not self._going_offline and
                                time.time() - last_presence >= _PRESENCE_HEARTBEAT_S):
                            last_presence = time.time()
                            await self._publish(ws, ("presence", "online"))
                        try:
                            item_type, first = await asyncio.wait_for(
                                self._queue.get(), timeout=_PRESENCE_HEARTBEAT_S / 2)
                        except asyncio.TimeoutError:
                            continue
                        if item_type == "typing":
                            if time.time() - first.get("_enqueued_at", time.time()) > _LIVENESS_DROP_AFTER_S:
                                self._stale_drops += 1  # r8 M-E: visible en ops
                                if self._stale_drops % 10 == 1:
                                    logger.info("Buzz observer: %d stale frames dropped so far", self._stale_drops)
                                continue  # r3 M4: stale typing bypassed the drop before
                            # Latency-sensitive: publish solo, no batching.
                            await self._publish(ws, ("typing", first["tags"]))
                            backoff = 1.0
                            if not (self._stopping or self._going_offline):
                                await asyncio.sleep(_PUBLISH_MIN_INTERVAL_S)
                            continue
                        now = time.time()
                        if now - first.get("_enqueued_at", now) > _LIVENESS_DROP_AFTER_S:
                            self._stale_drops += 1  # r8 M-E
                            if self._stale_drops % 10 == 1:
                                logger.info("Buzz observer: %d stale frames dropped so far", self._stale_drops)
                            continue  # stale — relay freshness is ±5 min
                        batch = [first]
                        while len(batch) < 8 and not self._queue.empty():
                            nxt_type, nxt = self._queue.get_nowait()
                            if nxt_type == "typing":
                                # r5 H1: never burst typing — requeue and stop
                                # batching so it gets the pacer like everything
                                # else (it drains on the next loop pass).
                                self._queue.put_nowait((nxt_type, nxt))
                                break
                            # r5 M2: batch envelope carries ONE channelId/turnId
                            # — never coalesce events from another channel/turn.
                            if (nxt.get("channelId") != first.get("channelId")
                                    or nxt.get("turnId") != first.get("turnId")):
                                self._queue.put_nowait((nxt_type, nxt))
                                break
                            if now - nxt.get("_enqueued_at", now) <= _LIVENESS_DROP_AFTER_S:
                                batch.append(nxt)
                        await self._publish(ws, batch)
                        backoff = 1.0
                        if not (self._stopping or self._going_offline):
                            # r6 H1 + r7 H-C: el drain de shutdown es sin pacer
                            # DESDE mark_going_offline — _stopping solo se fija
                            # en begin_shutdown, DESPUES del flush(1.2s), asi que
                            # confiar solo en el dejaba el pacer activo mientras
                            # drenaban los cancels sinteticos.
                            await asyncio.sleep(_PUBLISH_MIN_INTERVAL_S)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Auth failures are configuration problems (wrong BUZZ_AUTH_TAG)
                # and must be loud; transport drops reconnect quietly after the
                # first warning (r2 finding F — no silent infinite retry).
                self._reconnects += 1
                if _phase == "auth":
                    logger.error("Buzz observer: relay auth failed (%s) — check "
                                 "BUZZ_AUTH_TAG / relay URL; retrying in %.0fs", exc, backoff)
                elif self._reconnects == 1:
                    logger.warning("Buzz observer: publisher reconnect (%s); retrying "
                                   "with backoff", exc)
                else:
                    logger.debug("Buzz observer: publisher reconnect #%d (%s)",
                                 self._reconnects, exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX_S)
