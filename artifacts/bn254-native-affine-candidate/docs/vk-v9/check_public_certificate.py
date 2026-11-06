#!/usr/bin/env python3
"""PUB003 v9 supplement: fixed BN254/VK/TAG/R bindings over the v8 decoder."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
V8_PATH = HERE / "codec_v8.py"
BN254_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
BN254_X = 4965661367192848881
VK_DIGEST = "181aeefd9c0ce8d103ad084f4ef8174546852b0af46ac58a8061d4f38d346a6e"
TAG_PREFIX = b"BNMX3/DEGREE6-EVAL1"


def load_v8():
    spec = importlib.util.spec_from_file_location("pub003_v8_decoder", V8_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("v8 decoder unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def need(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def final_literal_push(v8, unlocking_hex: str, redeem: bytes) -> None:
    data = bytes.fromhex(unlocking_hex)
    offset = 0
    last_end = -1
    last_payload = None
    while offset < len(data):
        opcode = data[offset]
        if opcode <= 75 or opcode in (0x4c, 0x4d):
            end, payload = v8.read_push(data, offset)
            last_end, last_payload = end, payload
            offset = end
        else:
            offset += 1
    need(last_end == len(data), "R is not the final literal push")
    need(last_payload == redeem, "positive input final R does not equal current redeem")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check fixed BN254/VK/TAG/R public certificate bindings")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--positive-vectors", required=True, type=Path)
    parser.add_argument("--certificate-inputs", required=True, type=Path)
    args = parser.parse_args()
    v8 = load_v8()

    # Reuse the already-passed public native decoder and table/GLS checks. Its
    # output is suppressed so this version emits one machine-readable result.
    original_argv = sys.argv[:]
    try:
        sys.argv = [original_argv[0], "--bundle", str(args.bundle), "--fixture", str(args.fixture), "--positive-vectors", str(args.positive_vectors), "--certificate-inputs", str(args.certificate_inputs)]
        with contextlib.redirect_stdout(io.StringIO()):
            v8.main()
    finally:
        sys.argv = original_argv

    bundle = json.loads(args.bundle.read_text())
    artifact = bundle["artifact"]
    fixture = json.loads(args.fixture.read_text())
    vectors = json.loads(args.positive_vectors.read_text())
    certificate = json.loads(args.certificate_inputs.read_text())
    field = certificate["field"]
    need(int(field["p"]) == BN254_P, "certificate p is not BN254 base field")
    need(int(field["r"]) == BN254_R, "certificate r is not BN254 scalar field")
    need(int(field["bnX"]) == BN254_X, "certificate BN_X is not pinned BN254")
    need(field["modulus"] == "X^12-18X^6+82", "BN254 tower modulus")

    words = v8.fixture_words(fixture)
    need(len(words) == 20, "VK word count")
    encoded_words = b"".join(int(word, 10).to_bytes(32, "little") for word in words)
    need(all(0 <= int(word, 10) < BN254_P for word in words), "VK word outside canonical base-field range")
    need(sha256(encoded_words) == VK_DIGEST, "canonical VK LE32 digest")
    need(bytes.fromhex(artifact["functionBodies"]["TRANS"]["codeHex"]), "TRANS body")
    trans = bytes.fromhex(artifact["functionBodies"]["TRANS"]["codeHex"])
    decoded = v8.decode_instructions(trans)
    need(decoded and decoded[0][1] == len(TAG_PREFIX) + 32, "TRANS TAG push boundary")
    need(decoded[0][2] == TAG_PREFIX + bytes.fromhex(VK_DIGEST), "TRANS TAG/VK digest binding")

    redeem = bytes.fromhex(artifact["redeemHex"])
    steps = vectors["steps"]
    need(len(steps) >= 3, "three canonical positive inputs")
    for index, step in enumerate(steps[:3]):
        need(step["locking"] == v8.EXPECTED_LOCKING, f"locking row {index}")
        final_literal_push(v8, step["unlocking"], redeem)

    result = {
        "schema": "public-pub003-vk-table-native-binding/v9",
        "status": "PASS_PUB003_FIXED_BN254_VK_TAG_AND_ALL_POSITIVE_R_BINDINGS",
        "v8Decoder": str(V8_PATH.relative_to(HERE.parent.parent.parent)),
        "bn254": {"p": str(BN254_P), "r": str(BN254_R), "bnX": str(BN254_X)},
        "vk": {"words": 20, "encoding": "unsigned decimal fixture words encoded as canonical little-endian 32-byte values", "sha256": VK_DIGEST},
        "tag": {"prefixAscii": TAG_PREFIX.decode("ascii"), "bytes": len(TAG_PREFIX) + 32, "digest": VK_DIGEST},
        "positive": {"rowsChecked": 3, "finalRedeemSha256": sha256(redeem), "locking": v8.EXPECTED_LOCKING},
        "qualification": False,
        "relationProofSeparate": True,
        "scope": "Fixed BN254 constants, canonical VK digest, TRANS TAG commitment, and all-three positive final-R bindings added to v8's public native/body/table/GLS checks; pairing relation, VM/compiler semantics, resource theorem, and full qualification remain separate.",
        "supersedes": "prior fixed-VK/native-table evidence without all row bindings",
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, FileNotFoundError, json.JSONDecodeError, ValueError, OverflowError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
