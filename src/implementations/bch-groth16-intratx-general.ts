// BCH-native Groth16 verifier — INTRA-TRANSACTION LINKED, TOKENLESS + RUNTIME-GENERAL, the
// whole BN254 Groth16 verification in ONE standard-sized transaction (< 100,000 B on the wire).
//
// Same single-tx forward-checking mechanism as bch-groth16-intratx / -residue: each chunk is an
// INPUT of ONE transaction whose witness carries its incoming state as a raw byte blob and
// require()s the next input's blob — read via tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE)
// — equals its recomputed output. There is NO NFT-commitment hand-off, NO hashing bottleneck, and
// NO 128-byte token-commitment limit; state is bound by direct byte equality across siblings.
//
// Two properties distinguish this entry from the residue intra-tx build:
//
//   TOKENLESS  — every input carries ONLY {locking, unlocking}; there is no CashToken/NFT covenant
//                anywhere in the transaction. The running state (the gb3-narrow Miller interior, the
//                vk_x MSM boundary, the residue witness) rides the scored unlocking witness bytes,
//                forward-pinned to each successor's witness front and read back with OP_INPUTBYTECODE.
//                All state therefore counts toward the on-chain score; there is no off-wire channel.
//
//   RUNTIME-GENERAL — the 13 input lockings are proof-INDEPENDENT: byte-identical across four
//                distinct standard-magnitude proofs, one dense near-r worst-case proof, and the
//                invalids (lockConcatSha256 below). Only the unlockings differ per proof. In
//                particular the finalize step-64 fixed-pair Frobenius add-points are NOT baked
//                instance constants: they are re-derived on-chain from the psi chain
//                q1=psi(B), q2=psi^2(B), q3=psi^3(B) that the subgroup fold already computes for the
//                R_end == -psi^3(B) tie, and ENFORCED == psi(witnessed B) (strictly stronger than a
//                trusted-baked add-point). A baked-proof program cannot pass the harness multiproof
//                sweep; this one does.
//
// Chunk graph (13 inputs, one transaction):
//   input 0        lib          2 B bare push (shared constant/library front)
//   inputs 1..9    exec0..exec8 the gb3-narrow batched Miller interior (10 identical-locking chunks)
//   input 10       genesis      subgroup fold + vk_x ECIP-MSM merged into the genesis input
//   input 11       finalize     step-64 finalize with on-chain-derived (de-baked) Frobenius points
//   input 12       fused        c^-(6x+2)-fused close + terminal residue verdict
//
// STATEMENT. The SAME fixed Groth16 statement as the other BN254 entries: two public inputs,
// vk_x = IC0 + in0*IC1 + in1*IC2, canonical trusted setup in src/checkpoints/pairing-vectors.json.
// The four extraValidProofs (public inputs [439832,401604], [158496,392375], [168759,939020]) and the
// default [42540,732739] each verify against that VK under @noble/curves/bn254 (e(-A,B)e(alpha,beta)
// e(vk_x,gamma)e(C,delta)==1); the worst-case run uses dense near-r public inputs (2^253-1).
//
// SOUNDNESS (why a forged proof cannot satisfy the 13 inputs):
//   - The verifier enforces the full Groth16 pairing product == 1 over the fused Miller + residue
//     close; a proof that does not satisfy the equation leaves a non-ONE Fp12 residue and the fused
//     terminal REJECTs (invalid F3: off-curve C.x; invalid FB2: wrong public input — both reject).
//   - B is checked on-curve AND in the order-r subgroup on-chain via the psi fold R_end==-psi^3(B);
//     an on-twist off-subgroup B (invalid FB1) is rejected at genesis[10] + fused[12].
//   - The chunk chain is stapled by byte-equality forward-pinning (OP_INPUTBYTECODE): reorder,
//     truncate, zero-fill, splice, or delete any interior blob and the successor's equality check
//     fails. Because the lockings are proof-independent, splicing one proof's stage onto another
//     proof's remaining stages is rejected (cross-instance splices reject).
//
// This is a single transaction (structure single-tx: intra-tx linked inputs), scored as
// Sigma(locking)=422 B + Sigma(unlocking)=94,200 B = 94,622 B script bytes; with the serialized-tx
// overhead the on-wire transaction is ~94,779 B (< 100,000 B, i.e. within the standard max-tx-size).
//
// PROVENANCE. Contract source is private (a CashScript build + a bytecode assembler). Published
// here: the committed bytecode (the vectors), an honest construction description, and the sha256 of
// each of the 13 locking bytecodes (P2SH32 redeem-hash envelopes; input 0 is a bare 2-byte push):
//
//   idx  label      locking sha256
//   0    lib        33198a9bfef674ebddb9ffaa52928017b8472791e54c609cb95f278ac6b1e349
//   1..9 exec0..8   4642a501ef7b6a14aeb26cddca7282bc8bfc1962dd03500223698011ead7595b   (all 9 identical)
//   10   genesis    b9eb34ca4fc9884bcbb519d771c6dac2e19e86208c8b5d02a03ebb18bc025517
//   11   finalize   9b5763528941d49b996e1049c44ddbdea0d065ef5493aee46acfc6339ea6ac4b
//   12   fused      f5f47d7721ff6fbb203881633887c40dd3de01e8dbab756d79cab268afedd8c5
//
//   lockConcatSha256 = 3c917b6756a6173e3d6593ed44a41b0daf091ffee4e819b846857daad9104e48
//     (sha256 of the 13 locking bytecodes concatenated; byte-identical across every run below).
//
// Vectors: src/bch/groth16-intratx-general-vectors.json (valid + 3 extra proofs + worst-case +
// 3 invalids: FB1 off-subgroup B, FB2 wrong public input, F3 off-curve C.x).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-intratx-general-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array,
// so each step is evaluated against the same multi-input transaction (and its
// tx.inputs[idx±1] introspection resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({
    label: s.label,
    lockingBytecode: inputs[i]!.lockingBytecode,
    unlockingBytecode: inputs[i]!.unlockingBytecode,
    checkpoint: s.checkpoint,
    intraTx: { index: i, inputs },
  }));
};

export const bchGroth16IntratxGeneral: Implementation = {
  id: 'bch-groth16-intratx-general',
  name: 'BCH Groth16 intra-tx linked — tokenless + runtime-general (whole BN254 verifier in one standard-sized transaction)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the full BN254 Groth16 verifier laid out as the 13 linked INPUTS of ONE ' +
    'transaction. Same intra-tx forward-checking as bch-groth16-intratx (each input carries its ' +
    'incoming state as a raw byte blob and binds the chain via tx.inputs[idx+1].unlockingBytecode ' +
    'introspection — no NFT-commitment hand-off, no hashing, no 128-byte state limit), but TOKENLESS ' +
    '(no CashToken/NFT covenant anywhere; state rides the scored unlocking witness) and RUNTIME-GENERAL ' +
    'with de-baked finalize add-points: the step-64 fixed-pair Frobenius points are re-derived on-chain ' +
    'from the psi chain q1=psi(B), q2=psi^2(B), q3=psi^3(B) and enforced == psi(witnessed B), so the ' +
    'genesis/finalize redeems are proof-independent and the 13 lockings are byte-identical across all ' +
    'proofs (lockConcatSha256 3c917b6756a6173e3d6593ed44a41b0daf091ffee4e819b846857daad9104e48). ' +
    'Graph: 1 lib front (2 B) + 9 gb3-narrow batched-Miller exec chunks + genesis (subgroup fold + ' +
    'vk_x ECIP-MSM merged in) + finalize (de-baked Frobenius) + c^-(6x+2)-fused close with terminal ' +
    'residue verdict. B is on-curve + order-r-subgroup checked on-chain (psi fold R_end==-psi^3(B)); ' +
    'off-subgroup B, wrong public input, and off-curve coordinates all reject. Deployed as P2SH32 so ' +
    'each input\'s redeem rides in the scriptSig (counting toward the op-cost budget). Every input fits ' +
    'one BCH input budget (scripts <= 10,000 B); the whole verifier is one transaction of ~94,779 B on ' +
    'the wire (score: Sigma lock 422 + Sigma unlock 94,200 = 94,622 B script bytes). One fixed set of ' +
    'input scripts verifies any proof for the canonical VK (proof supplied in the witness).',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
