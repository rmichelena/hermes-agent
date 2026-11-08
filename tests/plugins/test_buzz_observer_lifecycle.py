"""Buzz observer telemetry — state, adapter hooks, and the loop against a real socket.

The loop tests run the publisher against a local ``websockets`` server that
plays the relay (NIP-42 challenge, OK receipts), so what is asserted is what
crossed the wire, decrypted with the owner's key.
"""

import asyncio
import contextlib
import importlib.util
import json
import sys
import time
import types
from pathlib import Path

import pytest
import websockets

_PLUGIN_DIR = Path(__file__).parents[2] / "plugins" / "platforms" / "buzz"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


observer = _load("buzz_observer_lifecycle_under_test", _PLUGIN_DIR / "observer.py")
adapter_mod = _load("buzz_adapter_lifecycle_under_test", _PLUGIN_DIR / "adapter.py")
ProcessingOutcome = adapter_mod.ProcessingOutcome

_AGENT_PRIV = "01" * 32
_OWNER_PRIV = "02" * 32
_OWNER_PUB = observer.public_key_hex(_OWNER_PRIV)
_AUTH_TAG = json.dumps(["auth", _OWNER_PUB, "", "00" * 64])


def _publisher(relay_url="ws://127.0.0.1:1"):
    return observer.ObserverPublisher(private_key=_AGENT_PRIV, auth_tag_json=_AUTH_TAG,
                                      relay_url=relay_url, session_id="sess-test")


def _event(chat_id, message_id, thread_id=None, chat_type="group"):
    return types.SimpleNamespace(
        source=types.SimpleNamespace(chat_id=chat_id, chat_type=chat_type, thread_id=thread_id),
        message_id=message_id)


# ── state: what is due ────────────────────────────────────────────────────────

def _kinds(due):
    return [kind for kind, _payload, _turn in due.events]


def test_start_and_end_in_one_tick_publish_both_in_order():
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub.turn_completed(ev, "ok")
        due = pub._due(100.0)
        assert _kinds(due) == ["turn_started", "turn_completed"]
        pub._commit(due, 100.0)
        assert not pub._turns
    asyncio.run(run())


def test_liveness_every_ten_seconds_after_start():
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root="r1", is_dm=False)
        pub._commit(pub._due(100.0), 100.0)
        assert _kinds(pub._due(109.9)) == []
        due = pub._due(110.0)
        assert _kinds(due) == ["turn_liveness"]
        assert due.events[0][1] == {"threadRootEventId": "r1"}
    asyncio.run(run())


def test_completion_recorded_while_publishing_is_not_lost():
    """``_commit`` must only drop a turn whose completion was IN the published frame."""
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        due = pub._due(100.0)  # carries turn_started only
        pub.turn_completed(ev, "ok")  # lands while that frame is on the wire
        pub._commit(due, 100.0)
        assert _kinds(pub._due(100.5)) == ["turn_completed"]
    asyncio.run(run())


def test_one_channel_per_frame_others_wait_for_next_tick():
    async def run():
        pub = _publisher()
        a, b, c = object(), object(), object()
        pub.turn_started(a, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub.turn_started(b, channel_id="c2", message_id="m2", thread_root=None, is_dm=False)
        pub.turn_started(c, channel_id="c1", message_id="m3", thread_root=None, is_dm=False)
        first = pub._due(100.0)
        assert first.channel_id == "c1" and len(first.events) == 2
        pub._commit(first, 100.0)
        second = pub._due(101.0)
        assert second.channel_id == "c2" and _kinds(second) == ["turn_started"]
    asyncio.run(run())


def test_overlapping_turns_in_one_chat_are_distinct():
    """In-band follow-ups open a second turn in the same chat with the first still open."""
    async def run():
        pub = _publisher()
        outer, followup = _event("c1", "m1"), _event("c1", "m2")
        for ev in (outer, followup):
            pub.turn_started(ev, channel_id="c1", message_id=ev.message_id, thread_root=None, is_dm=False)
        pub.turn_completed(followup, "ok")
        due = pub._due(100.0)
        ids = {t.turn_id for _k, t, *_ in due.turns}
        assert len(ids) == 2
        pub._commit(due, 100.0)
        assert [t.start_payload["triggeringEventIds"] for t in pub._turns.values()] == [["m1"]]
    asyncio.run(run())


def test_unknown_or_repeated_completion_is_ignored():
    async def run():
        pub = _publisher()
        pub.turn_completed(object(), "ok")
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id=None, thread_root=None, is_dm=True)
        pub.turn_completed(ev, "error")
        pub.turn_completed(ev, "ok")
        assert [p for k, p, _t in pub._due(1.0).events if k == "turn_completed"] == [{"outcome": "error"}]
    asyncio.run(run())


def test_typing_is_throttled_per_channel_and_thread():
    async def run():
        pub = _publisher()
        pub.typing("c1", None)
        due = pub._due(time.monotonic())
        assert [k for k, _t in due.typing] == [("c1", None)]
        pub._commit(due, time.monotonic())
        pub.typing("c1", None)
        assert pub._due(time.monotonic()).typing == []  # < 3 s since the last one
        assert [k for k, _ in pub._due(time.monotonic() + 3.1).typing] == [("c1", None)]
    asyncio.run(run())


def _tool_updates(due):
    return [(p["params"]["update"]["sessionUpdate"], p["params"]["update"].get("title"),
             p["params"]["update"]["status"]) for k, p, _t in due.events if k == "acp_read"]


def test_tool_status_becomes_acp_tool_call_and_update():
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub.tool_status("c1", "running pytest")
        pub.tool_status("c1", None)
        due = pub._due(100.0)
        assert _kinds(due) == ["turn_started", "acp_read", "acp_read"]
        assert _tool_updates(due) == [("tool_call", "Running pytest", "in_progress"),
                                      ("tool_call_update", None, "completed")]
        ids = {p["params"]["update"]["toolCallId"] for k, p, _t in due.events if k == "acp_read"}
        assert len(ids) == 1
        frame = next(p for k, p, _t in due.events if k == "acp_read")
        assert frame["method"] == "session/update" and frame["params"]["sessionId"] == "sess-test"
        pub._commit(due, 100.0)
        assert _kinds(pub._due(100.5)) == []  # sent once
    asyncio.run(run())


def test_a_new_phrase_closes_the_open_tool_and_the_turn_end_closes_the_last():
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub.tool_status("c1", "reading a")
        pub.tool_status("c1", "reading b")
        pub.turn_completed(ev, "ok")
        assert _tool_updates(pub._due(1.0)) == [
            ("tool_call", "Reading a", "in_progress"), ("tool_call_update", None, "completed"),
            ("tool_call", "Reading b", "in_progress"), ("tool_call_update", None, "completed")]
        assert _kinds(pub._due(1.0))[-1] == "turn_completed"
    asyncio.run(run())


def test_tool_status_goes_to_the_newest_open_turn_of_that_chat_only():
    async def run():
        pub = _publisher()
        old, new, other = object(), object(), object()
        for ev, ch in ((old, "c1"), (other, "c2"), (new, "c1")):
            pub.turn_started(ev, channel_id=ch, message_id=None, thread_root=None, is_dm=False)
        pub.tool_status("c1", "x")
        pub.tool_status("nowhere", "y")  # no open turn there: dropped
        assert [len(t.tool_frames) for t in pub._turns.values()] == [0, 0, 1]
    asyncio.run(run())


def test_close_ends_an_open_tool_before_the_turn():
    async def run():
        relay = FakeRelay()
        async with _serve(relay) as url:
            pub = _publisher(url)
            pub.start()
            await _until(lambda: 20001 in relay.kinds())
            pub.turn_started(object(), channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
            pub.tool_status("c1", "long tool")
            await _until(lambda: any(f["kind"] == "acp_read" for f in relay.observer_frames()))
            await pub.close(timeout=2.5)
        frames = relay.observer_frames()
        updates = [f["payload"]["params"]["update"]["sessionUpdate"] for f in frames if f["kind"] == "acp_read"]
        assert updates == ["tool_call", "tool_call_update"]
        kinds = [f["kind"] for f in frames]
        assert kinds.index("turn_completed") > max(i for i, k in enumerate(kinds) if k == "acp_read")
    asyncio.run(run())


def test_tool_frames_spill_over_ticks_in_order_and_the_end_waits(monkeypatch):
    monkeypatch.setattr(observer, "MAX_EVENTS_PER_FRAME", 4)

    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        for i in range(3):
            pub.tool_status("c1", f"t{i}")
        pub.tool_status("c1", None)  # 6 tool frames
        pub.turn_completed(ev, "ok")
        seen, now = [], 100.0
        while pub._turns:
            due = pub._due(now)
            seen += [k if k != "acp_read" else p["params"]["update"].get("title") or "end"
                     for k, p, _t in due.events]
            if now == 100.0:
                pub.tool_status("c1", None)  # lands mid-publish: a no-op here, nothing open
            pub._commit(due, now)
            now += 1
        assert seen == ["turn_started", "T0", "end", "T1", "end", "T2", "end", "turn_completed"]
    asyncio.run(run())


def test_a_tool_frame_recorded_while_publishing_is_kept():
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub.tool_status("c1", "first")
        due = pub._due(100.0)
        pub.tool_status("c1", "second")  # on the wire meanwhile: closes "first", opens "second"
        pub._commit(due, 100.0)
        assert _tool_updates(pub._due(101.0)) == [("tool_call_update", None, "completed"),
                                                  ("tool_call", "Second", "in_progress")]
    asyncio.run(run())


@pytest.mark.parametrize("phrase,title", [
    ("is reading foo.py…", "Reading foo.py"), ("is running `pytest -q`…", "Running `pytest -q`"),
    ("lee foo.py…", "Lee foo.py"), ("is  searching\nthe   web…", "Searching the web"), ("…", "")])
def test_status_phrase_becomes_a_title(phrase, title):
    assert observer._tool_title(phrase) == title


def test_an_interrupted_tool_fails_and_a_finished_turn_completes_it():
    async def run():
        pub = _publisher()
        ok, stopped = object(), object()
        pub.turn_started(ok, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub.tool_status("c1", "a")
        pub.turn_completed(ok, "ok")
        pub.turn_started(stopped, channel_id="c2", message_id="m2", thread_root=None, is_dm=False)
        pub.tool_status("c2", "b")
        pub.turn_completed(stopped, "cancelled")
        statuses = {t.channel_id: [f["params"]["update"]["status"] for f in t.tool_frames]
                    for t in pub._turns.values()}
        assert statuses == {"c1": ["in_progress", "completed"], "c2": ["in_progress", "failed"]}
    asyncio.run(run())


def test_the_cap_drops_whole_pairs_and_keeps_an_unannounced_end():
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub.tool_status("c1", "first")
        due = pub._due(1.0)
        first_id = next(p["params"]["update"]["toolCallId"] for k, p, _t in due.events if k == "acp_read")
        pub._commit(due, 1.0)  # "first" announced; its end will be alone at the head
        for i in range(observer.MAX_TOOL_FRAMES_PER_TURN):
            pub.tool_status("c1", f"t{i}")
        frames = pub._turns[id(ev)].tool_frames
        assert len(frames) <= observer.MAX_TOOL_FRAMES_PER_TURN
        assert frames[0]["params"]["update"] == {  # the end of an announced tool is never dropped
            "sessionUpdate": "tool_call_update", "toolCallId": first_id, "status": "completed"}
        ids = [f["params"]["update"]["toolCallId"] for f in frames[1:]]
        starts = [f["params"]["update"]["toolCallId"] for f in frames[1:]
                  if f["params"]["update"]["sessionUpdate"] == "tool_call"]
        assert all(i in starts for i in ids)  # no end without its start
    asyncio.run(run())


def test_status_from_a_worker_thread_lands_on_the_loop_in_order():
    import threading

    async def run():
        relay = FakeRelay()
        async with _serve(relay) as url:
            pub = _publisher(url)
            pub.start()
            pub.turn_started(object(), channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
            loop_thread = threading.get_ident()
            seen_threads = []
            original = pub.tool_status

            def spy(channel_id, phrase):
                seen_threads.append(threading.get_ident())
                original(channel_id, phrase)

            pub.tool_status = spy
            worker = threading.Thread(target=lambda: [pub.post_tool_status("c1", p) for p in ("a", None, "b")])
            worker.start()
            await asyncio.to_thread(worker.join)
            await asyncio.sleep(0.05)
            assert seen_threads == [loop_thread] * 3
            titles = [f["params"]["update"].get("title") for t in pub._turns.values() for f in t.tool_frames]
            assert titles == ["A", None, "B"]
            await pub.close(timeout=1.0)
    asyncio.run(run())


def test_no_tool_opens_once_closing():
    async def run():
        pub = _publisher()
        ev = object()
        pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
        pub._closing.set()
        pub.tool_status("c1", "late")
        assert pub._turns[id(ev)].tool_frames == []
    asyncio.run(run())


def test_a_busy_turn_never_overflows_a_frame():
    async def run():
        pub = _publisher()
        ck = observer.get_conversation_key(_OWNER_PRIV, observer.public_key_hex(_AGENT_PRIV))
        evs = [object() for _ in range(40)]
        for ev in evs:
            pub.turn_started(ev, channel_id="c1", message_id="e" * 64, thread_root="r" * 64, is_dm=False)
        for _ in range(observer.MAX_TOOL_FRAMES_PER_TURN):
            pub.tool_status("c1", "z" * 5000)
        for ev in evs:
            pub.turn_completed(ev, "ok")
        now, ticks = 100.0, 0
        while pub._turns and ticks < 100:
            due = pub._due(now)
            events = [pub._observer_event(k, p, channel_id=t.channel_id, turn_id=t.turn_id,
                                          started_at=t.started_at) for k, p, t in due.events]
            frame = pub._observer_frame(events)
            assert len(observer.nip44_decrypt(frame["content"], ck).encode()) < 65535
            pub._commit(due, now)
            now, ticks = now + 1, ticks + 1
        assert not pub._turns
    asyncio.run(run())


def test_open_turn_cap_forgets_the_oldest():
    async def run():
        pub = _publisher()
        events = [object() for _ in range(observer.MAX_OPEN_TURNS + 1)]
        for i, ev in enumerate(events):
            pub.turn_started(ev, channel_id="c1", message_id=f"m{i}", thread_root=None, is_dm=False)
        assert len(pub._turns) == observer.MAX_OPEN_TURNS
        assert id(events[0]) not in pub._turns and id(events[-1]) in pub._turns
    asyncio.run(run())


def test_bad_owner_in_auth_tag_is_rejected_at_construction():
    bad = json.dumps(["auth", "ff" * 32, "", "00" * 64])  # >= field prime
    try:
        observer.ObserverPublisher(private_key=_AGENT_PRIV, auth_tag_json=bad, relay_url="ws://x")
    except ValueError:
        return
    raise AssertionError("an owner outside the field must not reach NIP-44")


# ── the loop, through a real socket ──────────────────────────────────────────

class FakeRelay:
    """Plays the relay: NIP-42 challenge, then OK for every EVENT (or a scripted answer)."""

    def __init__(self, *, accept_auth=True, answer_auth=True, deny_with=None):
        self.accept_auth, self.answer_auth = accept_auth, answer_auth
        self.deny_with = deny_with  # None | "notice" | "close"
        self.events: list[dict] = []
        self.connections = 0

    async def handler(self, ws):
        self.connections += 1
        await ws.send(json.dumps(["AUTH", "challenge-1"]))
        async for raw in ws:
            msg = json.loads(raw)
            if msg[0] == "AUTH":
                if self.deny_with == "notice":
                    await ws.send(json.dumps(["NOTICE", "restricted: authorization denied"]))
                elif self.deny_with == "close":
                    await ws.close()
                    return
                elif self.answer_auth:
                    await ws.send(json.dumps(["OK", msg[1]["id"], self.accept_auth,
                                              "" if self.accept_auth else "restricted: bad auth tag"]))
            elif msg[0] == "EVENT":
                self.events.append(msg[1])
                await ws.send(json.dumps(["OK", msg[1]["id"], True, ""]))

    def observer_frames(self):
        ck = observer.get_conversation_key(_OWNER_PRIV, observer.public_key_hex(_AGENT_PRIV))
        out = []
        for ev in self.events:
            if ev["kind"] == observer.OBSERVER_KIND:
                plain = json.loads(observer.nip44_decrypt(ev["content"], ck))
                out += plain["payload"]["events"] if plain["kind"] == "batch" else [plain]
        return out

    def kinds(self):
        return [ev["kind"] for ev in self.events]


@contextlib.asynccontextmanager
async def _serve(relay):
    async with websockets.serve(relay.handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"


async def _until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached"
        await asyncio.sleep(0.02)


def test_turn_round_trip_then_goodbye_on_the_wire():
    async def run():
        relay = FakeRelay()
        async with _serve(relay) as url:
            pub = _publisher(url)
            pub.start()
            await _until(lambda: 20001 in relay.kinds())  # authenticated, online
            ev = _event("c1", "m1")
            pub.turn_started(ev, channel_id="c1", message_id="m1", thread_root=None, is_dm=False)
            pub.typing("c1", None)
            await _until(lambda: any(f["kind"] == "turn_started" for f in relay.observer_frames()))
            open_turn = _event("c2", "m2")
            pub.turn_started(open_turn, channel_id="c2", message_id="m2", thread_root=None, is_dm=False)
            pub.turn_completed(ev, "ok")
            t0 = time.monotonic()
            await pub.close(timeout=2.5)
            assert time.monotonic() - t0 < 2.6
        frames = relay.observer_frames()
        kinds = [f["kind"] for f in frames]
        assert kinds[0] == "harness_started"
        done = {f["channelId"]: f["payload"] for f in frames if f["kind"] == "turn_completed"}
        assert done["c1"] == {"outcome": "ok"}
        assert done["c2"] == {"outcome": "cancelled", "reason": "gateway_shutdown"}
        started = {f["channelId"]: f["turnId"] for f in frames if f["kind"] == "turn_started"}
        assert {f["channelId"]: f["turnId"] for f in frames if f["kind"] == "turn_completed"} == started
        assert 20002 in relay.kinds()
        presence = [ev["content"] for ev in relay.events if ev["kind"] == 20001]
        assert presence[0] == "online" and presence[-1] == "offline"
        assert relay.kinds()[-1] == 20001
    asyncio.run(run())


def test_close_is_bounded_when_the_relay_never_answers():
    async def run():
        relay = FakeRelay(answer_auth=False)  # hangs after the challenge
        async with _serve(relay) as url:
            pub = _publisher(url)
            pub.start()
            await _until(lambda: relay.connections == 1)
            task = pub._task
            t0 = time.monotonic()
            await pub.close(timeout=1.0)
            assert time.monotonic() - t0 < 1.2
            assert task.done(), "close() must not leave the socket owner running"
    asyncio.run(run())


def test_rejected_auth_is_an_error_and_publishes_nothing(caplog):
    async def run():
        relay = FakeRelay(accept_auth=False)
        async with _serve(relay) as url:
            pub = _publisher(url)
            pub.start()
            await _until(lambda: "check BUZZ_AUTH_TAG" in caplog.text)
            await pub.close(timeout=1.0)
        assert relay.events == []
    caplog.set_level("ERROR")
    asyncio.run(run())


def test_auth_denial_by_notice_or_close_is_reported_once_and_backs_off(caplog):
    async def run(deny_with):
        relay = FakeRelay(deny_with=deny_with)
        async with _serve(relay) as url:
            pub = _publisher(url)
            pub.start()
            await asyncio.sleep(2.5)  # backoff 1 s then 2 s: at most two dials
            await pub.close(timeout=1.0)
        assert relay.events == []
        assert 1 <= relay.connections <= 2, relay.connections
    caplog.set_level("DEBUG")
    for mode, text in (("notice", "restricted: authorization denied"), ("close", "socket closed during AUTH")):
        caplog.clear()
        asyncio.run(run(mode))
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1 and text in errors[0].getMessage()


def test_a_full_channel_never_builds_an_oversized_frame():
    async def run():
        pub = _publisher()
        ck = observer.get_conversation_key(_OWNER_PRIV, observer.public_key_hex(_AGENT_PRIV))
        for i in range(observer.MAX_OPEN_TURNS):
            pub.turn_started(object(), channel_id="c1", message_id="e" * 64, thread_root="r" * 64, is_dm=False)
        now, published = 100.0, 0
        while pub._turns and published < observer.MAX_OPEN_TURNS:
            due = pub._due(now)
            events = [pub._observer_event(k, p, channel_id=t.channel_id, turn_id=t.turn_id,
                                          started_at=t.started_at) for k, p, t in due.events]
            frame = pub._observer_frame(events)
            assert len(observer.nip44_decrypt(frame["content"], ck).encode()) < 65535
            published += len(due.turns)
            pub._commit(due, now)
            now += 1.0
        assert published == observer.MAX_OPEN_TURNS
    asyncio.run(run())


def test_relay_down_at_start_recovers_when_it_comes_up():
    async def run():
        relay = FakeRelay()
        async with _serve(relay) as url:
            port = int(url.rsplit(":", 1)[1])
        pub = _publisher(url)  # nothing listens on the port any more
        pub.start()
        await asyncio.sleep(0.3)
        async with websockets.serve(relay.handler, "127.0.0.1", port):
            await _until(lambda: 20001 in relay.kinds(), timeout=8.0)
            await pub.close(timeout=1.0)
    asyncio.run(run())


# ── adapter hooks ────────────────────────────────────────────────────────────

class RecordingObserver:
    def __init__(self):
        self.calls = []

    def turn_started(self, token, **kw):
        self.calls.append(("start", token, kw))

    def turn_completed(self, token, outcome, reason=None):
        self.calls.append(("end", token, outcome))

    def typing(self, chat_id, thread_root=None):
        self.calls.append(("typing", chat_id, thread_root))

    def post_tool_status(self, chat_id, phrase):
        self.calls.append(("tool", chat_id, phrase))

    async def close(self, timeout):
        self.calls.append(("close", timeout))


def _bare_adapter(obs):
    a = object.__new__(adapter_mod.BuzzAdapter)
    a._observer = obs
    a.observer_telemetry = obs is not None
    a._OK_EMOJI = a._FAIL_EMOJI = None
    a._mark_disconnected = lambda: None
    a._release_platform_lock = lambda: None
    a._ws_task = a._poll_task = None
    a._channel_state = {}
    a._poll_count = 0
    return a


def test_hooks_pass_the_event_object_as_turn_identity():
    async def run():
        obs = RecordingObserver()
        a = _bare_adapter(obs)
        ev = _event("c1", "m1", thread_id="r1", chat_type="dm")
        await a.on_processing_start(ev)
        await a.on_processing_complete(ev, ProcessingOutcome.CANCELLED)
        (_s, t1, kw), (_e, t2, outcome) = obs.calls
        assert t1 is ev and t2 is ev
        assert kw == {"channel_id": "c1", "message_id": "m1", "thread_root": "r1", "is_dm": True}
        assert outcome == "cancelled"
    asyncio.run(run())


def test_typing_carries_the_thread_and_disconnect_closes_once():
    async def run():
        obs = RecordingObserver()
        a = _bare_adapter(obs)
        await a.send_typing("c1", {"thread_id": "r1"})
        await a.disconnect()
        await a.disconnect()
        assert obs.calls == [("typing", "c1", "r1"), ("close", 2.0)]
        assert a._observer is None
    asyncio.run(run())


def test_a_failing_observer_close_cannot_leave_the_inbound_transport_running():
    async def run():
        class Exploding(RecordingObserver):
            async def close(self, timeout):
                raise RuntimeError("boom")
        a = _bare_adapter(Exploding())
        a._ws_task = asyncio.create_task(asyncio.sleep(3600))
        await a.disconnect()
        assert a._ws_task is None and a._observer is None
    asyncio.run(run())


def test_status_line_reaches_the_observer_only_when_it_is_on():
    obs = RecordingObserver()
    a = _bare_adapter(obs)
    assert a.supports_status_text is True
    a.set_status_text("c1", "running pytest")
    a.set_status_text("c1", None)
    assert obs.calls == [("tool", "c1", "running pytest"), ("tool", "c1", None)]
    off = _bare_adapter(None)
    assert off.supports_status_text is False  # the gateway then never builds phrases for Buzz
    off.set_status_text("c1", "x")


def test_telemetry_off_leaves_hooks_and_typing_inert():
    async def run():
        a = _bare_adapter(None)
        ev = _event("c1", "m1")
        await a.on_processing_start(ev)
        await a.on_processing_complete(ev, ProcessingOutcome.SUCCESS)
        await a.send_typing("c1", None)
        await a.disconnect()
    asyncio.run(run())


def test_bad_auth_tag_disables_telemetry_without_failing_connect(caplog):
    a = _bare_adapter(None)
    a.observer_telemetry = True
    a._private_key, a._auth_tag, a.relay_url = _AGENT_PRIV, "not json", "ws://127.0.0.1:1"
    a._start_observer()
    a._start_observer()
    assert a._observer is None and a.observer_telemetry is False
    assert caplog.text.count("observer telemetry disabled") == 1
