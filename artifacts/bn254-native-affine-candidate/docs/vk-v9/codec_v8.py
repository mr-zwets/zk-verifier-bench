#!/usr/bin/env python3
"""PUB003 public certificate checker with byte-bound native decoding.

This checker consumes only the current public bundle, public fixture, positive
vectors, and the portable certificate-input supplement.  It does not import
the verifier, a private catalog, or a runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


EXPECTED_CODE = "63f12474082916e22ab62faf6c6f0483bedcbb08a9700e4d7eb02415c9d8c242"
EXPECTED_REDEEM = "00ca02340f7f75537f7751ca02530e7f75537f777e76a82063f12474082916e22ab62faf6c6f0483bedcbb08a9700e4d7eb02415c9d8c242885189518a"
EXPECTED_REDEEM_SHA = "0563cd756e2d300b7653e10fd2e39ba5951e404210ba78f18d8ba4549719a030"
EXPECTED_LOCKING = "aa2021affd236254692aee253595380dc929d405df472af03f772879a386f952e7c287"
EXPECTED_TABLE_HASHES = {
    "R00": "da1e0f3825b1d49b6bb042e49dc1e5f073f772d122e3e72a53c62d0252f9f97e",
    "R01": "76047bcea692a83f62c138ee0cdccb066db95693e19296de605bf13e801114cf",
    "R10": "330fe6e088ef04bd39e8a2e17dc8cd20c9687db32a24973fd019274a7518994e",
    "R11": "d88de8a365643c826c0017d3fcb976f3e7a7506ad9db7e5a1d6b7c71022e52b9",
    "Rconst": "b6cd472f318146d7743be63b48c1756b995f98c9415bcb496f6c641341448efb",
}
BODY_NAMES = ["P", "RD", "EV", "EA", "TM", "TA", "G1C", "PLEN", "FILL", "GRAPH", "TRANS", "STMT", "HDEC", "HENC", "SETUP", "BDBL", "BADD", "DSTEP", "ADDSTEP", "BNDSTEP", "LOOP", "role0", "role1", "role2"]
EXPECTED_BODY_IDS = {
    "P": 6, "RD": 8, "EV": 12, "EA": 11, "TM": 13, "TA": 22,
    "G1C": 9, "PLEN": 3, "FILL": 2, "GRAPH": 4, "TRANS": 5,
    "STMT": 7, "HDEC": 15, "HENC": -1, "SETUP": 10, "BDBL": 21,
    "BADD": 0, "DSTEP": 16, "ADDSTEP": 17, "BNDSTEP": 19, "LOOP": 14,
    "role0": 23, "role1": 24, "role2": 25,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(message: str) -> None:
    raise AssertionError(message)


def fixture_words(value: dict) -> list[str]:
    vk = value["vk"]
    words: list[str] = []
    for key in ("alpha", "beta", "gamma", "delta"):
        for coordinate in ("x", "y"):
            item = vk[key][coordinate]
            words.extend([item] if isinstance(item, str) else [item["c0"], item["c1"]])
    for point in vk["ic"]:
        words.extend([point["x"], point["y"]])
    return words


def read_push(data: bytes, offset: int) -> tuple[int, bytes]:
    """Read one Script push and return (next offset, payload)."""
    if offset >= len(data):
        fail(f"push beyond end at {offset}")
    opcode = data[offset]
    if opcode <= 75:
        length = opcode
        start = offset + 1
    elif opcode == 0x4c:
        if offset + 2 > len(data):
            fail("truncated PUSHDATA1")
        length = data[offset + 1]
        start = offset + 2
    elif opcode == 0x4d:
        if offset + 3 > len(data):
            fail("truncated PUSHDATA2")
        length = int.from_bytes(data[offset + 1:offset + 3], "little")
        start = offset + 3
    else:
        fail(f"non-push opcode {opcode:#x} at {offset}")
    end = start + length
    if end > len(data):
        fail(f"truncated push at {offset}")
    return end, data[start:end]


def read_pushnum(data: bytes, offset: int) -> tuple[int, int]:
    opcode = data[offset]
    if opcode == 0:
        return offset + 1, 0
    if opcode == 0x4f:
        return offset + 1, -1
    if 0x51 <= opcode <= 0x60:
        return offset + 1, opcode - 0x50
    end, payload = read_push(data, offset)
    if not payload:
        return end, 0
    value = int.from_bytes(payload, "little", signed=False)
    if payload[-1] & 0x80:
        value -= 1 << (8 * len(payload))
    return end, value


def decode_instructions(body: bytes) -> list[tuple[int, int, bytes | None]]:
    """Decode boundaries; only pushes carry payloads."""
    out: list[tuple[int, int, bytes | None]] = []
    offset = 0
    while offset < len(body):
        opcode = body[offset]
        if opcode <= 75 or opcode in (0x4c, 0x4d):
            end, payload = read_push(body, offset)
            out.append((offset, opcode, payload))
            offset = end
        else:
            out.append((offset, opcode, None))
            offset += 1
    return out


def decode_prologue(code: bytes, expected_count: int) -> tuple[list[tuple[int, bytes]], bytes]:
    """Parse pushData(body), pushNum(functionId), OP_DEFINE triples."""
    offset = 0
    definitions: list[tuple[int, bytes]] = []
    for _ in range(expected_count):
        offset, body = read_push(code, offset)
        offset, function_id = read_pushnum(code, offset)
        if offset >= len(code) or code[offset] != 0x89:
            fail(f"missing OP_DEFINE after function {function_id}")
        offset += 1
        definitions.append((function_id, body))
    return definitions, code[offset:]


def parse_positive_input(unlocking_hex: str, c_length: int, redeem: bytes | None = None) -> bytes:
    data = bytes.fromhex(unlocking_hex)
    offset, c = read_push(data, 0)
    if len(c) != c_length:
        fail(f"positive C length {len(c)} != {c_length}")
    if redeem is not None:
        offset, _ = read_push(data, offset)  # S
        offset, _ = read_push(data, offset)  # DS
        if offset >= len(data) or data[offset] != 0:
            fail("positive input lacks the expected OP_0 before R")
        offset += 1
        offset, r = read_push(data, offset)
        if r != redeem or offset != len(data):
            fail("positive input R does not bind exactly to current redeem")
    return c


def determinant(matrix: list[list[int]]) -> int:
    if len(matrix) == 1:
        return matrix[0][0]
    return sum(((-1) ** j) * matrix[0][j] * determinant([row[:j] + row[j + 1:] for row in matrix[1:]]) for j in range(len(matrix)))


def check_gls(certificate: dict) -> None:
    field = certificate["field"]
    p, r, x = (int(field[key]) for key in ("p", "r", "bnX"))
    assert field["flattenBasisDegrees"] == [0, 2, 4, 1, 3, 5]
    gls = certificate["gls"]
    pi = [1, p % r, (p * p) % r, (p ** 3) % r]
    assert [int(value) for value in gls["pi"]] == pi
    lattice = [[int(value) for value in row] for row in gls["lattice"]]
    expected = [[2 * x + 1, 0, 2 * x, 1], [2 * x, x + 1, -x, x], [x + 1, x, x, -2 * x], [2 * x + 1, -x, -(x + 1), -x]]
    assert lattice == expected
    assert all(sum(row[i] * pi[i] for i in range(4)) % r == 0 for row in lattice)
    assert abs(determinant(lattice)) == r
    cofactor = [((-1) ** j) * determinant([row[1:] for i, row in enumerate(lattice) if i != j]) for j in range(4)]
    assert cofactor == [int(value) for value in gls["cofactorFirstColumn"]]
    sums = [sum(abs(row[i]) for row in lattice) for i in range(4)]
    assert sums == [int(value) for value in gls["columnAbsSums"]]
    assert all(value < 2 ** 65 for value in sums)
    assert gls["bits"] == 65 and int(gls["offset"]) == 2 ** 64


def main() -> int:
    parser = argparse.ArgumentParser(description="Check public PUB003 native table certificate")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--positive-vectors", required=True, type=Path)
    parser.add_argument("--certificate-inputs", required=True, type=Path)
    args = parser.parse_args()

    bundle_bytes = args.bundle.read_bytes()
    fixture_bytes = args.fixture.read_bytes()
    vectors_bytes = args.positive_vectors.read_bytes()
    certificate_bytes = args.certificate_inputs.read_bytes()
    bundle = json.loads(bundle_bytes)
    artifact = bundle["artifact"]
    code = bytes.fromhex(artifact["codeHex"])
    redeem = bytes.fromhex(artifact["redeemHex"])
    assert sha256(code) == EXPECTED_CODE == artifact["codeSha256"]
    assert redeem.hex() == EXPECTED_REDEEM and sha256(redeem) == EXPECTED_REDEEM_SHA == artifact["redeemSha256"]

    fixture = json.loads(fixture_bytes)
    certificate = json.loads(certificate_bytes)
    words = fixture_words(fixture)
    assert words == certificate["vkWords"] and len(words) == 20
    assert sha256(",".join(words).encode()) == certificate["vkWordsSha256"]
    assert fixture["artifactSha256"] == "dc10764f1e6bafad2727538ed33d51134e7bc04a349e7ac138415474beaa2747"
    check_gls(certificate)

    vectors = json.loads(vectors_bytes)
    steps = vectors["steps"]
    assert len(steps) >= 3 and all(step["locking"] == EXPECTED_LOCKING for step in steps)
    c0 = parse_positive_input(steps[0]["unlocking"], 3889, redeem)
    c1 = parse_positive_input(steps[1]["unlocking"], 3664)
    pieces = [bytes.fromhex(value) for value in artifact["codePiecesHex"]]
    assert artifact["codePieces"] == [3889, 3664]
    assert [len(value) for value in pieces] == [3889, 3664]
    assert pieces == [c0, c1] and b"".join(pieces) == code
    assert artifact["layout"]["fixed"][0][0] == ["C", 3889]
    assert artifact["layout"]["fixed"][1][0] == ["C", 3664]
    assert artifact["layout"]["off"][0]["C"]["data"] == 3
    assert artifact["layout"]["off"][1]["C"]["data"] == 3

    bodies = artifact["functionBodies"]
    assert list(bodies) == BODY_NAMES
    body_by_bytes: dict[bytes, str] = {}
    for name in BODY_NAMES:
        body = bytes.fromhex(bodies[name]["codeHex"])
        assert len(body) == int(bodies[name]["bytes"]) and sha256(body) == bodies[name]["sha256"]
        if body in body_by_bytes:
            fail(f"duplicate function body {name}/{body_by_bytes[body]}")
        body_by_bytes[body] = name
    definitions, tail = decode_prologue(code, len(BODY_NAMES))
    assert tail == bytes.fromhex("c00117938a")
    bound: dict[str, int] = {}
    for function_id, body in definitions:
        name = body_by_bytes.get(body)
        if name is None:
            fail(f"native prologue body is absent from public functionBodies (id {function_id})")
        if name in bound:
            fail(f"duplicate native body binding for {name}")
        assert EXPECTED_BODY_IDS[name] == function_id
        bound[name] = function_id
    assert set(bound) == set(BODY_NAMES)
    assert [bound[name] for name in ("role0", "role1", "role2")] == artifact["roleFunctionIds"] == [23, 24, 25]

    tables = certificate["tables"]
    emitted: dict[str, int] = {}
    table_sequences: dict[str, list[int]] = {}
    for name in tables:
        values = tables[name]
        assert len(values) == 7 and values[-1] == "1"
        assert sha256(",".join(values).encode()) == EXPECTED_TABLE_HASHES[name]
        table_sequences[name] = [int(value).to_bytes(32, "little") for value in values[:6]]

    def locate(body: bytes, name: str) -> int:
        decoded = decode_instructions(body)
        wanted = table_sequences[name]
        hits: list[int] = []
        for index in range(len(decoded) - 5):
            window = decoded[index:index + 6]
            if all(opcode == 0x20 and payload is not None for _, opcode, payload in window) and [payload for _, _, payload in window] == wanted:
                hits.append(window[0][0])
        if len(hits) != 1:
            fail(f"{name}: decoded table sequence count {len(hits)}")
        return hits[0]

    for name in ("R00", "R01", "R10", "R11"):
        emitted[name] = locate(bytes.fromhex(bodies["SETUP"]["codeHex"]), name)
    emitted["Rconst"] = locate(bytes.fromhex(bodies["role2"]["codeHex"]), "Rconst")
    assert code[-5:] == bytes.fromhex("c00117938a")
    assert c1[-5:] == bytes.fromhex("c00117938a")

    refs = {
        "bundle": {"path": str(args.bundle), "bytes": len(bundle_bytes), "sha256": sha256(bundle_bytes)},
        "fixture": {"path": str(args.fixture), "bytes": len(fixture_bytes), "sha256": sha256(fixture_bytes)},
        "positiveVectors": {"path": str(args.positive_vectors), "bytes": len(vectors_bytes), "sha256": sha256(vectors_bytes)},
        "certificateInputs": {"path": str(args.certificate_inputs), "bytes": len(certificate_bytes), "sha256": sha256(certificate_bytes)},
    }
    print(json.dumps({
        "status": "PASS_PUB003_PUBLIC_INPUT_BOUND_NATIVE_TABLE_CERTIFICATE",
        "refs": refs,
        "bundleCodeSha256": EXPECTED_CODE,
        "bundleRedeemSha256": EXPECTED_REDEEM_SHA,
        "codePieces": [3889, 3664],
        "positiveCExtraction": {"step0Bytes": len(c0), "step1Bytes": len(c1), "lockingRows": len(steps)},
        "nativePrologue": {"definitions": len(definitions), "boundFunctionIds": bound, "dispatcherTailHex": tail.hex()},
        "nativeTableEmissionInstructionOffsets": emitted,
        "vkWords": 20,
        "glsRows": 4,
        "runtimeImports": 0,
        "vmRuns": 0,
        "relationProofSeparate": True,
        "qualification": False,
        "scope": "public C/R/locking binding, actual native prologue/body/ID binding, instruction-boundary table emission, and independent GLS arithmetic; raw Miller-to-monic relation remains separately scoped",
        "supersedes": "claims-vk-table-certificate-v7-unadmitted-instruction-boundary-claim",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
