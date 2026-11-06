"""Buzz observer telemetry — NIP-44 v2 port and event builders.

The crypto is validated against the complete official paulmillr/nip44
vectors (tests/fixtures/nip44.vectors.json, from
javascript/test/nip44.vectors.json) so the wire format cannot drift.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PLUGIN_DIR = Path(__file__).parents[2] / "plugins" / "platforms" / "buzz"
_spec = importlib.util.spec_from_file_location(
    "buzz_observer_under_test", _PLUGIN_DIR / "observer.py")
assert _spec is not None and _spec.loader is not None
observer = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = observer
_spec.loader.exec_module(observer)

_VECTORS = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "nip44.vectors.json").read_text())["v2"]["valid"]

_TEST_PRIV = "01" * 32  # deterministic test key (hex form)


@pytest.mark.parametrize("v", _VECTORS["get_conversation_key"])
def test_conversation_key_vector(v):
    assert observer.get_conversation_key(v["sec1"], v["pub2"]).hex() == v["conversation_key"]


def test_message_keys_vector():
    spec = _VECTORS["get_message_keys"]
    ck = bytes.fromhex(spec["conversation_key"])
    for v in spec["keys"]:
        ckk, cn, mk = observer._get_message_keys(ck, bytes.fromhex(v["nonce"]))
        assert (ckk.hex(), cn.hex(), mk.hex()) == \
            (v["chacha_key"], v["chacha_nonce"], v["hmac_key"])


@pytest.mark.parametrize("n,want", _VECTORS["calc_padded_len"])
def test_calc_padded_len(n, want):
    assert observer._calc_padded_len(n) == want


@pytest.mark.parametrize("v", _VECTORS["encrypt_decrypt"])
def test_encrypt_vector(v):
    pub2 = observer.public_key_hex(v["sec2"])
    ck = observer.get_conversation_key(v["sec1"], pub2)
    assert ck.hex() == v["conversation_key"]
    got = observer.nip44_encrypt(v["plaintext"], ck, bytes.fromhex(v["nonce"]))
    assert got == v["payload"]
    assert observer.nip44_decrypt(got, ck) == v["plaintext"]


def _bare_publisher():
    pub = observer.ObserverPublisher.__new__(observer.ObserverPublisher)
    pub.priv = _TEST_PRIV
    pub.agent_pub = observer.public_key_hex(_TEST_PRIV)
    pub.session_id = "sess-test"
    from itertools import count
    pub._seq = count(1)
    return pub


def test_observer_event_shape():
    pub = _bare_publisher()
    ev = observer.ObserverPublisher._observer_event(
        pub, "turn_started", channel_id="ch", turn_id="t",
        started_at="2026-11-06T00:00:00+00:00",
        payload={"source": "channel", "triggeringEventIds": ["e1"]})
    assert ev["kind"] == "turn_started"
    assert ev["channelId"] == "ch" and ev["sessionId"] == "sess-test"
    assert ev["agentIndex"] == 0 and ev["seq"] == 1
    assert ev["payload"]["triggeringEventIds"] == ["e1"]


def test_typing_event_wire():
    pub = _bare_publisher()
    ev = observer.ObserverPublisher._build_typing_event(
        pub, [["h", "chan-1"], ["e", "root-1", "", "root"]])
    assert ev["kind"] == 20002
    assert ev["content"] == ""
    assert ev["tags"] == [["h", "chan-1"], ["e", "root-1", "", "root"]]
    assert len(ev["sig"]) == 128


def test_presence_event_wire():
    pub = _bare_publisher()
    ev = observer.ObserverPublisher._build_presence_event(pub, "offline")
    assert ev["kind"] == 20001
    assert ev["content"] == "offline"
    assert ev["tags"] == [["status", "offline"]]
    assert len(ev["sig"]) == 128
