// A runnable multi-transaction demo that exercises the harness's multi-tx
// support using the exact mechanism BCH's Groth16 verifier will use: state
// carried forward across steps via a hash256 commitment (see the repo's
// multi-step-computation.md). It is NOT a real verifier; it is the smallest
// faithful multi-step chain so the harness's multi-tx path can be validated and
// benchmarked. Each step:
//   unlock:  <state_i>
//   lock:    OP_DUP OP_HASH256 <hash(state_i)> OP_EQUALVERIFY   // check incoming state
//            OP_1ADD OP_HASH256 <hash(state_i + 1)> OP_EQUAL     // commit outgoing state
// so step i's outgoing commitment equals step i+1's incoming commitment.
import { bigIntToVmNumber, OpcodesBch, sha256 } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const hash256 = (x: Uint8Array): Uint8Array => sha256.hash(sha256.hash(x));
const numEnc = (n: bigint): Uint8Array => bigIntToVmNumber(n);
const push = (d: Uint8Array): number[] => [d.length, ...d]; // d.length <= 75 here

const STEPS = 3;
const START = 1_000_000n;

const makeStep = (i: bigint): Step => {
  const inHash = hash256(numEnc(START + i));
  const outHash = hash256(numEnc(START + i + 1n));
  const lockingBytecode = Uint8Array.from([
    OpcodesBch.OP_DUP,
    OpcodesBch.OP_HASH256,
    ...push(inHash),
    OpcodesBch.OP_EQUALVERIFY,
    OpcodesBch.OP_1ADD,
    OpcodesBch.OP_HASH256,
    ...push(outHash),
    OpcodesBch.OP_EQUAL,
  ]);
  return {
    label: `step ${Number(i) + 1}/${STEPS}`,
    lockingBytecode,
    unlockingBytecode: Uint8Array.from(push(numEnc(START + i))),
  };
};

export const bchMultistepDemo: Implementation = {
  id: 'bch-multistep-demo',
  name: 'BCH multi-step demo (hash-chained state)',
  proofSystem: 'demo (hash-chained state)',
  field: '-',
  structure: 'multi-tx',
  demo: true,
  source: 'synthetic; mirrors multi-step-computation.md',
  load: async () => {
    const valid = Array.from({ length: STEPS }, (_, i) => makeStep(BigInt(i)));
    // tag a couple of steps as checkpoints so the benchmark reports the
    // cumulative op-cost + bytes to reach them (stand-ins for vk_x / boundary).
    valid[0]!.checkpoint = 'milestone-1';
    valid[STEPS - 1]!.checkpoint = 'milestone-final';
    return { valid, tamperable: true };
  },
};
