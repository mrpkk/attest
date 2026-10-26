"""S5: конверт COSE_Sign1 и служба прозрачности.

Гейт: квитанция регистрируема (G8 — конверт с CWT claims), включение
проверяется офлайн, подмена после регистрации обнаруживается.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attest.receipt import cbor, cose, jcs, log as tlog

PAYLOAD = b'{"spec":"noa.receipt/0.1"}'


@pytest.fixture()
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def envelope(priv, **over) -> bytes:
    kw = dict(kid="k1", issuer="acme", subject="chain-1")
    kw.update(over)
    return cose.wrap(PAYLOAD, private_key=priv, **kw)


def test_envelope_round_trips(keys):
    priv, pub = keys
    result = cose.verify(envelope(priv), pub)
    assert result.ok, result.reason
    assert result.payload == PAYLOAD
    assert result.kid == "k1"
    assert result.issuer == "acme"
    assert result.subject == "chain-1"
    assert "protected header" in result.notes[0]


def test_envelope_is_registrable_shape(keys):
    """G8: тег 18, alg -19, kid и CWT claims в защищённой шапке."""
    priv, _ = keys
    parsed = cbor.loads(envelope(priv))
    assert isinstance(parsed, cbor.Tag) and parsed.number == 18
    protected = cbor.loads(parsed.value[0])
    assert protected[1] == -19
    assert protected[4] == b"k1"
    assert protected[15] == {1: "acme", 2: "chain-1"}


def test_tampered_payload_is_rejected(keys):
    priv, pub = keys
    parsed = cbor.loads(envelope(priv))
    parsed.value[2] = PAYLOAD + b" "
    broken = cbor.dumps(parsed)
    assert not cose.verify(broken, pub).ok


def test_wrong_alg_is_rejected(keys):
    priv, pub = keys
    protected = cbor.dumps({1: -8, 4: b"k1", 15: {1: "acme", 2: "chain-1"}})
    sig = priv.sign(cose.sig_structure(protected, PAYLOAD))
    broken = cbor.dumps(cbor.Tag(18, [protected, {}, PAYLOAD, sig]))
    result = cose.verify(broken, pub)
    assert not result.ok
    assert "-19" in result.reason


def test_missing_cwt_claims_are_rejected(keys):
    priv, pub = keys
    protected = cbor.dumps({1: -19, 4: b"k1"})
    sig = priv.sign(cose.sig_structure(protected, PAYLOAD))
    broken = cbor.dumps(cbor.Tag(18, [protected, {}, PAYLOAD, sig]))
    result = cose.verify(broken, pub)
    assert not result.ok
    assert "CWT_Claims" in result.reason


def test_cwt_claims_in_both_buckets_are_rejected(keys):
    priv, pub = keys
    protected = cbor.dumps({1: -19, 4: b"k1", 15: {1: "acme", 2: "chain-1"}})
    sig = priv.sign(cose.sig_structure(protected, PAYLOAD))
    broken = cbor.dumps(cbor.Tag(18, [protected, {15: {1: "x", 2: "y"}}, PAYLOAD, sig]))
    assert not cose.verify(broken, pub).ok


def test_untagged_structure_is_rejected(keys):
    priv, pub = keys
    parsed = cbor.loads(envelope(priv))
    untagged = cbor.dumps(parsed.value)
    result = cose.verify(untagged, pub)
    assert not result.ok
    assert "tag 18" in result.reason


def test_non_deterministic_cbor_is_rejected(keys):
    priv, pub = keys
    good = envelope(priv)
    # 0x18 0x01 — не shortest form для 1; ставим его перед структурой.
    assert not cose.verify(b"\x18\x01" + good, pub).ok


def test_unprotected_kid_is_reported_as_naming_nobody(keys):
    priv, pub = keys
    protected = cbor.dumps({1: -19, 15: {1: "acme", 2: "chain-1"}})
    sig = priv.sign(cose.sig_structure(protected, PAYLOAD))
    env = cbor.dumps(cbor.Tag(18, [protected, {4: b"k1"}, PAYLOAD, sig]))
    result = cose.verify(env, pub)
    assert result.ok
    assert "names nobody" in result.notes[0]


# --- журнал ---------------------------------------------------------------


def test_append_and_inclusion(tmp_path):
    priv = Ed25519PrivateKey.generate()
    lg = tlog.TransparencyLog(tmp_path / "log.txt")
    for i in range(5):
        lg.append(b"statement-%d" % i)
    head = lg.head(priv)
    assert head.size == 5
    proof = lg.inclusion(2)
    leaves = lg.leaves
    assert tlog.verify_inclusion(bytes.fromhex(proof["leaf"]), 2, head.size,
                                 [bytes.fromhex(h) for h in proof["proof"]],
                                 bytes.fromhex(head.root))


def test_tampered_proof_fails(tmp_path):
    lg = tlog.TransparencyLog(tmp_path / "log.txt")
    for i in range(4):
        lg.append(b"s-%d" % i)
    head = lg.head()
    proof = [bytes.fromhex(h) for h in lg.inclusion(1)["proof"]]
    proof[0] = b"\x00" * 32
    assert not tlog.verify_inclusion(lg.leaves[1], 1, head.size, proof, bytes.fromhex(head.root))


def test_consistency_between_two_heads(tmp_path):
    lg = tlog.TransparencyLog(tmp_path / "log.txt")
    for i in range(3):
        lg.append(b"a-%d" % i)
    old = lg.head()
    for i in range(3, 8):
        lg.append(b"a-%d" % i)
    new = lg.head()
    proof = [bytes.fromhex(h) for h in lg.consistency(3)["proof"]]
    assert tlog.verify_consistency(3, new.size, proof,
                                   bytes.fromhex(old.root), bytes.fromhex(new.root))


def test_consistency_fails_for_wrong_old_root(tmp_path):
    lg = tlog.TransparencyLog(tmp_path / "log.txt")
    for i in range(5):
        lg.append(b"b-%d" % i)
    new = lg.head()
    proof = [bytes.fromhex(h) for h in lg.consistency(2)["proof"]]
    assert not tlog.verify_consistency(2, new.size, proof, b"\x11" * 32, bytes.fromhex(new.root))


def test_tree_head_signature(tmp_path):
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    lg = tlog.TransparencyLog(tmp_path / "log.txt")
    lg.append(b"x")
    head = lg.head(priv)
    assert head.verify(priv.public_key().public_bytes_raw())
    assert not head.verify(other.public_key().public_bytes_raw())


def test_log_survives_restart(tmp_path):
    path = tmp_path / "log.txt"
    lg = tlog.TransparencyLog(path)
    lg.append(b"one")
    lg.append(b"two")
    again = tlog.TransparencyLog(path)
    assert again.leaves == lg.leaves
