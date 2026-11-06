"""Lifecycle tests for the Buzz observer telemetry integration (multireview M6).

Covers the turn-pairing keying (H1), orphan-completion skipping (M2), the
ordered capped shutdown (H2) and the relative sibling import (C1) without any
network or relay.
"""

import asyncio
import importlib.util
import json
import itertools
import sys
import types
from pathlib import Path

_PLUGIN_DIR = Path(__file__).parents[2] / "plugins" / "platforms" / "buzz"
_spec = importlib.util.spec_from_file_location(
    "buzz_adapter_under_test", _PLUGIN_DIR / "adapter.py")
assert _spec is not None and _spec.loader is not None
adapter_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = adapter_mod
_spec.loader.exec_module(adapter_mod)


class FakeObserver:
    def __init__(self):
        self.emitted = []
        self.flushed = False
        self.offline = False
        self.stopped = None
        self.published_log = []
        self._task = None
        self.going_offline = False
        self.began_shutdown = False

    def mark_going_offline(self):
        self.going_offline = True

    def begin_shutdown(self):
        self.began_shutdown = True
        self._stopping = True

    def emit(self, kind, **kw):
        self.emitted.append((kind, kw))

    async def flush(self, timeout_s=1.5):
        self.flushed = True

    async def publish_presence_standalone(self, status, budget_s=2.8):
        self.offline = status
        return True

    async def stop(self, grace_s=2.0):
        self.stopped = grace_s


def _event(chat_id, message_id, thread_id=None, chat_type="group"):
    return types.SimpleNamespace(
        source=types.SimpleNamespace(
            chat_id=chat_id, chat_type=chat_type, thread_id=thread_id),
        message_id=message_id)


def _bare_adapter(observer):
    a = object.__new__(adapter_mod.BuzzAdapter)
    a._observer = observer
    a._observer_turns = {}
    a._anon_turn_seq = itertools.count()
    a._typing_last = {}
    a._mark_disconnected = lambda: None
    a._release_platform_lock = lambda: None
    a._ws_task = None
    a._poll_task = None
    a._channel_state = {}
    a._poll_count = 0
    return a


def test_overlapping_turns_do_not_clobber():
    async def run():
        obs = FakeObserver()
        a = _bare_adapter(obs)
        await a.on_processing_start(_event("c1", "m1"))
        await a.on_processing_start(_event("c1", "m2"))  # in-band follow-up
        assert len(a._observer_turns) == 2, "both turns must stay open"
        starts = [k for k, _ in obs.emitted if k == "turn_started"]
        assert len(starts) == 2
        await a.on_processing_complete(_event("c1", "m2"), _SUCCESS)
        assert len(a._observer_turns) == 1 and ("c1", "m1") in a._observer_turns
        await a.on_processing_complete(_event("c1", "m1"), _SUCCESS)
        assert not a._observer_turns
        dones = [kw for k, kw in obs.emitted if k == "turn_completed"]
        assert [d["payload"]["outcome"] for d in dones] == ["ok", "ok"]
        # turn_ids must pair: completion i carries the turn_id its start made
        tids = [kw["turn_id"] for k, kw in obs.emitted if k == "turn_started"]
        assert {d["turn_id"] for d in dones} == set(tids)
    asyncio.run(run())


def test_orphan_completion_is_skipped():
    async def run():
        obs = FakeObserver()
        a = _bare_adapter(obs)
        await a.on_processing_complete(_event("c1", "never-started"), _SUCCESS)
        assert not [k for k, _ in obs.emitted if k == "turn_completed"], \
            "completion without an open turn must not fabricate a turnId (M2)"
    asyncio.run(run())


def test_shutdown_cancels_all_open_turns_then_offline_then_flush():
    async def run():
        obs = FakeObserver()
        a = _bare_adapter(obs)
        await a.on_processing_start(_event("c1", "m1"))
        await a.on_processing_start(_event("c2", "m2"))
        await a.disconnect()
        cancels = [kw for k, kw in obs.emitted if k == "turn_completed"]
        assert len(cancels) == 2
        assert all(c["payload"]["outcome"] == "cancelled" and
                   c["payload"]["reason"] == "gateway_shutdown" for c in cancels)
        assert obs.offline == "offline"
        assert obs.flushed and obs.going_offline and obs.began_shutdown
        assert not a._observer_turns
    asyncio.run(run())


def test_shutdown_total_budget_capped():
    async def run():
        class SlowObserver(FakeObserver):
            async def publish_presence_standalone(self, status, budget_s=2.8):
                await asyncio.sleep(30)  # simulates a hung relay
        obs = SlowObserver()
        a = _bare_adapter(obs)
        await a.on_processing_start(_event("c1", "m1"))
        import time
        t0 = time.monotonic()
        await a.disconnect()  # must return in ~4.2s, not 30 (H2)
        assert time.monotonic() - t0 < 4.6  # stop() included in the cap (r2 B)
    asyncio.run(run())


def test_sibling_import_is_relative():
    src = (_PLUGIN_DIR / "observer.py").read_text()
    assert '"/opt/hermes' not in src, "hardcoded install root must not remain (C1)"
    import subprocess
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, '.')\n"
         "import importlib.util as iu\n"
         f"spec = iu.spec_from_file_location('obs_c1', r'{_PLUGIN_DIR / 'observer.py'}')\n"
         "m = iu.module_from_spec(spec); sys.modules['obs_c1'] = m; spec.loader.exec_module(m)\n"
         "print('ok')"],
        cwd="/tmp", capture_output=True, text=True)
    assert "ok" in out.stdout, f"observer must import outside the install root: {out.stderr[-400:]}"


class _SUCCESS:
    name = "SUCCESS"


def test_heartbeat_refreshes_under_activity():
    """r2 A: presence must refresh by CLOCK even while telemetry keeps the
    queue permanently non-empty (liveness every 10s in real turns)."""
    import asyncio as _aio
    import queue as _queue

    class FakeWS:
        def __init__(self):
            self.responses = [["AUTH", "challenge"]]
            self.sent = []

        async def send(self, raw):
            self.sent.append(raw)
            msg = json.loads(raw)
            if msg[0] == "AUTH":
                # relay ACKs NIP-42 auth with an OK frame carrying the event id
                self.responses.append(["OK", msg[1]["id"], True])
            elif msg[0] == "EVENT":
                self.responses.append(["OK", msg[1]["id"], True])

        async def recv(self):
            while not self.responses:
                await _aio.sleep(0.01)
            return json.dumps(self.responses.pop(0))

    class FakeWSModule:
        @staticmethod
        def connect(*a, **k):
            ws = FakeWS()

            class _Ctx:
                async def __aenter__(self):
                    return ws

                async def __aexit__(self, *exc):
                    return False
            return _Ctx()

    async def run():
        obs_spec = importlib.util.spec_from_file_location(
            "obs_hb", _PLUGIN_DIR / "observer.py")
        obs = importlib.util.module_from_spec(obs_spec)
        sys.modules["obs_hb"] = obs
        obs_spec.loader.exec_module(obs)
        obs._PRESENCE_HEARTBEAT_S = 0.6  # compressed clock for the test
        saved_ws = sys.modules.get("websockets")
        sys.modules["websockets"] = FakeWSModule
        env = dict(private_key="01" * 32, auth_tag_json='["auth","4fd3b281f97e93f2b2302a791775330ac2a41ca1e97e12d9cdb64c74cc920357","2026-11-06T00:00:00Z","nonce"]',
                   relay_url="wss://test")
        pub = obs.ObserverPublisher(**env)
        pub.build_auth_event = lambda **k: {"kind": 22242}  # stub: auth shape
        try:
            await pub.start()
            # continuous activity: enqueue telemetry every 150ms — the queue
            # NEVER rests, which is exactly the r2 A repro condition
            for _ in range(14):
                pub.emit("turn_liveness", channel_id="c1", turn_id="t",
                         started_at="2026-11-06T00:00:00+00:00", payload={})
                await _aio.sleep(0.15)
            await pub.stop()
        finally:
            if saved_ws is not None:
                sys.modules["websockets"] = saved_ws
            else:
                sys.modules.pop("websockets", None)
        presence = [k for k, _ in pub.published_log if k == 20001]
        assert len(presence) >= 2, (
            f"presence must refresh by clock under activity, got {len(presence)} "
            f"in ~2.1s with 0.6s heartbeat (r2 A)")
    asyncio.run(run())  # r3-H2 verification: the body MUST actually run


def test_early_connection_failure_keeps_publisher_alive():
    """r3 H1: a relay that is DOWN at boot (connect raises before AUTH) must
    not kill the publisher with UnboundLocalError — it retries with backoff."""

    class DeadWSModule:
        @staticmethod
        def connect(*a, **k):
            async def _boom():
                raise OSError("connection refused (relay down at boot)")
            class _Ctx:
                async def __aenter__(self):
                    raise OSError("connection refused (relay down at boot)")
                async def __aexit__(self, *exc):
                    return False
            return _Ctx()

    async def run():
        obs_spec = importlib.util.spec_from_file_location(
            "obs_h1", _PLUGIN_DIR / "observer.py")
        obs = importlib.util.module_from_spec(obs_spec)
        sys.modules["obs_h1"] = obs
        obs_spec.loader.exec_module(obs)
        obs._RECONNECT_BACKOFF_MAX_S = 0.05  # compressed retry clock
        saved_ws = sys.modules.get("websockets")
        sys.modules["websockets"] = DeadWSModule
        pub = obs.ObserverPublisher(
            private_key="01" * 32, auth_tag_json='["auth","4fd3b281f97e93f2b2302a791775330ac2a41ca1e97e12d9cdb64c74cc920357","2026-11-06T00:00:00Z","nonce"]', relay_url="wss://test")
        try:
            await pub.start()
            await asyncio.sleep(2.2)  # backoff starts at 1s: 2+ attempts by now
        finally:
            if saved_ws is not None:
                sys.modules["websockets"] = saved_ws
            else:
                sys.modules.pop("websockets", None)
        assert pub._task is not None and not pub._task.done(), (
            "publisher task must survive early connection failures (r3 H1)")
        assert pub._reconnects >= 2, (
            f"expected multiple reconnect attempts, got {pub._reconnects}")
        await pub.stop()
    asyncio.run(run())


def test_anonymous_turns_complete_without_clobber():
    """r2 E: two message_id=None turns in one chat must open two entries and
    both completions must close them (oldest first)."""
    async def run():
        obs = FakeObserver()
        a = _bare_adapter(obs)
        e1 = _event("c1", None)
        e2 = _event("c1", None)
        await a.on_processing_start(e1)
        await a.on_processing_start(e2)
        assert len(a._observer_turns) == 2, "anon turns need unique keys (r2 E)"
        await a.on_processing_complete(_event("c1", None), _SUCCESS)
        await a.on_processing_complete(_event("c1", None), _SUCCESS)
        assert not a._observer_turns
        dones = [kw for k, kw in obs.emitted if k == "turn_completed"]
        assert len(dones) == 2 and all(d["payload"]["outcome"] == "ok" for d in dones)
    asyncio.run(run())

def test_registry_cap_evicts_oldest_and_keeps_tracking():
    """r7 H-A: 101 turnos — el mas viejo se evicta con turn_completed
    {registry_cap}, el turno 101 queda registrado, y el registro queda
    acotado a 100 (cap aplicado tras insertar: la eviction no puede
    bloquear el registro del turno nuevo)."""
    import asyncio

    async def run():
        obs = FakeObserver()
        a = _bare_adapter(obs)
        for i in range(101):
            await a.on_processing_start(_event("c1", f"m{i}"))
        # registro acotado: 101 inserts -> 1 eviction -> 100 vivos
        assert len(a._observer_turns) == 100, len(a._observer_turns)
        # la eviction emitio exactamente un registry_cap
        caps = [kw for kind, kw in obs.emitted
                if kind == "turn_completed"
                and (kw.get("payload") or {}).get("reason") == "registry_cap"]
        assert len(caps) == 1, len(caps)
        # el turno 101 (nuevo) esta registrado; el primero fue el evictado
        assert ("c1", "m100") in a._observer_turns
        assert ("c1", "m0") not in a._observer_turns
        # limpieza: cancelar liveness pendientes (evitado warnings)
        for t in a._observer_turns.values():
            lv = t.get("liveness")
            if lv is not None and not lv.done():
                lv.cancel()

    asyncio.run(run())

