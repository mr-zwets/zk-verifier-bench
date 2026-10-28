import type { ProofInput } from '../harness/types.js';

// Affine singleton ABI: reversed (Ax, Ay, Bx0, Bx1, By0, By1, Cx, Cy, in0, in1).
// gen-multiproof{,-bls12381}.mjs proofArgs/unlockingFor own this layout.
// Pushes 0/1 are public scalars; pushes 2..9 are proof coordinates.
export const affineSingletonProofInputs: ProofInput[] = Array.from(
  { length: 8 }, (_, index) => ({ input: 0, push: index + 2 }),
);
