// Evidence-based review status per registered implementation (the soundness reset of
// 2026-10, after the author withdrawals in groth16_cashscript#32 / zk-verifier-bench#49).
//   'reviewed'   - an independent soundness review of the exact shipped artifact found no gaps.
//   'unreviewed' - the author's / maintainer's claim only, with no open finding (the default).
//   'withdrawn'  - the author withdrew the claim, or a finding applies to the shipped artifact;
//                  a finding that is open but not yet confirmed is also held here. Never counts
//                  for the frontier leader / current or new history points.
//   'baseline'   - a third-party reference verifier (nChain, sCrypt), measured for comparison.
//   'demo'       - a harness self-test, not a verifier.
//   'component'  - a partial pairing / vk_x checkpoint (category 'partial'), not a full verifier.
//   'archived'   - a superseded legacy entry kept as history only; like 'withdrawn' it is never
//                  ranked (frontier leader / current, new history points), but its row stays.
// Withdrawn implementations are removed from REGISTRY (bench #50 removed the 15 rows of the reset;
// bch-groth16-bls12381-grouped-residue followed after the 2026-10-27 review); their rows then leave
// results.json entries[] too. The site keeps a frozen copy of
// those last rows (zk-verifier-competition src/data/withdrawn-archive.json). Only ids still in
// REGISTRY belong in this table.
// Kept as one table keyed by id (not on each implementation module) so registry removals
// stay independent edits; benchmark.ts attaches it to every REGISTRY entry.
import type { Implementation, ReviewStatus } from './types.js';

const SRC = 'https://github.com/mr-zwets/groth16_cashscript';
const BENCH = 'https://github.com/mr-zwets/zk-verifier-bench';
const FINDINGS = [`${SRC}/issues/32`, `${BENCH}/issues/49`];

const baseline: ReviewStatus = { status: 'baseline', reason: 'Third-party reference verifier, measured for comparison; not a verifier.cash entry.' };
const component: ReviewStatus = { status: 'component', reason: 'Partial pairing / vk_x component (checkpoint), not a full Groth16 verifier.' };
const archived: ReviewStatus = {
  status: 'archived',
  reason: 'Legacy large chain, superseded by the reviewed sound native and SI-GLS builds; kept as history, not ranked.',
};

// shared reasons for the BLS12-381 intratx-fs family (FS-PIT argument, chunked/bls12-381/README.md sections 1-6)
const FS_PIT = 'FS-PIT soundness argument, README sections 1-6, in the SHA-256 random-oracle model (bound (23*q_beta + 160*q_alpha)/2^256 + 3*N(N-1)/2^257 from README section 5: q counts adversary and verifier SHA-256 queries, q_beta/q_alpha the challenge queries among them, N adds the < 2^22 + 2^7 setup hashes). A and C are cofactor-equivalent.';
const FS_FAIL_CLOSED = ' The fail-closed binder-order argument in section 6 was accepted.';
const FS_REBUILD = ' Rebuilds byte-identically from the section 8 reconstructed flags.';
const FS_BINDER_FIRST = ' The binder runs first, before any loader, with root framing and a bounded prefix cache (section 6).';

/** statuses that never count for the frontier leader / current or new score-history points */
export const UNRANKED_STATUSES: ReadonlySet<ReviewStatus['status']> = new Set(['withdrawn', 'archived']);
export const isRanked = (status: ReviewStatus): boolean => !UNRANKED_STATUSES.has(status.status);

export const DEFAULT_REVIEW_STATUS: ReviewStatus = { status: 'unreviewed' };

export const REVIEW_STATUS: Record<string, ReviewStatus> = {
  // reviewed
  'bch-groth16-sound-si-gls-single': {
    status: 'reviewed',
    reason: 'Independent soundness review of the shipped artifact; see the soundness argument, verification and open risks in its README.',
    refs: [
      `${SRC}/blob/main/chunked/bn254/sound-si-gls/README.md#soundness-argument`,
      `${SRC}/blob/main/chunked/bn254/sound-si-gls/README.md#verification`,
      `${SRC}/blob/main/chunked/bn254/sound-si-gls/README.md#open-risks`,
    ],
  },

  // BLS12-381 SI-GLS (bch-spec): built on wip/bls-si-gls-spec; independent review 2026-10-26 (implementation,
  // math, reproduction) found only minor issues, all six fixed before merge (verifier.cash work/bls-si-gls-spec/FIXLOG.md).
  'bch-groth16-bls12381-sound-si-gls-single': {
    status: 'reviewed',
    reason: 'Independent soundness review of the shipped artifact (2026-10-26; implementation, math and reproduction, minor findings fixed before merge); see the soundness argument, verification and open risks in its README.',
    refs: [
      `${SRC}/blob/main/chunked/bls12-381/sound-si-gls/README.md#soundness-argument`,
      `${SRC}/blob/main/chunked/bls12-381/sound-si-gls/README.md#verification`,
      `${SRC}/blob/main/chunked/bls12-381/sound-si-gls/README.md#open-risks`,
    ],
  },

  // BN254 native (SI-MX3, 3-input bch-2026): built on wip/bn-native-sound; independent review 2026-10-26
  // (implementation, math, reproduction) found only minor issues, fixed or documented before merge
  // (verifier.cash work/bn-native-sound/FIXLOG.md).
  'bch-groth16-bn254-sound-native': {
    status: 'reviewed',
    reason: 'Independent soundness review of the shipped artifact (2026-10-26; implementation, math and reproduction, minor findings fixed or documented before merge); see the soundness argument, verification and open risks in its README.',
    refs: [
      `${SRC}/blob/main/chunked/bn254/bn-native-sound/README.md#soundness-argument-constructive-an-owner-for-every-value`,
      `${SRC}/blob/main/chunked/bn254/bn-native-sound/README.md#verification`,
      `${SRC}/blob/main/chunked/bn254/bn-native-sound/README.md#open-risks`,
    ],
  },

  // BLS12-381 sound native (4-input bch-2026 SI-GLS): built on wip/bls-native-sound; independent review 2026-10-26
  // (implementation, math, reproduction) found only minor issues, fixed or documented in two fix rounds before merge
  // (verifier.cash work/bls-native-sound/FIXLOG.md).
  'bch-groth16-bls12381-sound-native': {
    status: 'reviewed',
    reason: 'Independent soundness review of the shipped artifact (2026-10-26; implementation, math and reproduction, minor findings fixed or documented before merge); see the soundness argument, verification and open risks in its README.',
    refs: [
      `${SRC}/blob/main/chunked/bls12-381/bls-native-sound/README.md#soundness-argument`,
      `${SRC}/blob/main/chunked/bls12-381/bls-native-sound/README.md#verification`,
      `${SRC}/blob/main/chunked/bls12-381/bls-native-sound/README.md#open-risks`,
    ],
  },

  // BN254 singletons: independent review 2026-10-26 (notes: verifier.cash work/bn-singleton-review/REVIEW.md)
  // after the jacAddG1 right-identity fix (bench 15bf0fe). Its one LOW finding, missing
  // 0 <= v < p checks on the proof coordinates (encoding malleability only), is fixed in
  // groth16_cashscript 521460c and rebuilt here; the recompiler fix 35fe0f7 keeps those checks
  // in the opcode-optimized build.
  'bch-groth16-singleton': {
    status: 'reviewed',
    reason: 'independent review 2026-10-26: no soundness break; coordinate range checks added (review LOW finding: encoding malleability only).',
    refs: [`${SRC}/commit/521460c014bafe45b33b67dd061615141be8f37a`, `${SRC}/commit/78a42542451f7bf64072a89358e0bf0acc03a774`],
  },
  'bch-groth16-singleton-opcode-optimized': {
    status: 'reviewed',
    reason: 'independent review 2026-10-26: no soundness break; coordinate range checks added (review LOW finding: encoding malleability only).',
    refs: [`${SRC}/commit/521460c014bafe45b33b67dd061615141be8f37a`, `${SRC}/commit/35fe0f702794f5686238f43ed2bd4c8dd3ac32c4`, `${SRC}/commit/78a42542451f7bf64072a89358e0bf0acc03a774`],
  },

  // BLS12-381 singletons: the maintainer hold (no range/curve/subgroup checks) was resolved by the
  // domain checks added to groth16.cash (groth16_cashscript 14d139e, 974a691). Independent review
  // 2026-10-26 (notes: verifier.cash work/bls-singleton-review/REVIEW.md) found no soundness gaps;
  // its minor follow-ups (Bxa/Bxb/Bya/Cx +p rejection runs, README cofactor-malleability note) are
  // done in wip/bls-singleton-followups. Locking bytecode unchanged by the follow-ups.
  'bch-groth16-bls12381-singleton': {
    status: 'reviewed',
    reason: 'independent review 2026-10-26: no soundness break (range, curve and fused psi G2 subgroup checks verified); follow-ups done: non-canonical +p rejection runs for every coordinate, A/C cofactor malleability documented (malleability only).',
    refs: [`${SRC}/commit/974a6910eb6924cfdbb547ea2556f229d9790421`, `${SRC}/commit/47c1ab15bd837d21c016e2e61b948f0e94b5862b`, `${SRC}/blob/main/singleton/bls12-381/README.md#proof-point-validation`],
  },
  'bch-groth16-bls12381-singleton-opcode-optimized': {
    status: 'reviewed',
    reason: 'independent review 2026-10-26: no soundness break (range, curve and fused psi G2 subgroup checks verified); follow-ups done: non-canonical +p rejection runs for every coordinate, A/C cofactor malleability documented (malleability only).',
    refs: [`${SRC}/commit/974a6910eb6924cfdbb547ea2556f229d9790421`, `${SRC}/commit/47c1ab15bd837d21c016e2e61b948f0e94b5862b`, `${SRC}/blob/main/singleton/bls12-381/README.md#proof-point-validation`],
  },

  // genpow singletons: corrected successors (source #30/#31, bench #47/#48) reviewed in REVIEW-WF2 §2/§3;
  // shipped bytes re-confirmed byte for byte 2026-10-27 (notes: verifier.cash work/genpow-promotions/NOTES.md).
  'bch-groth16-singleton-genpow': {
    status: 'reviewed',
    reason: 'Independent review 2026-10-26/27 of the corrected 4,320 B program (sha 022fea80…): canonical coordinate and Fr guards, exact curve and psi G2 checks, complete MSM identity addition and neutral Miller units verified; no soundness gap. Native resource HOLD (op-cost).',
    refs: [...FINDINGS, `${SRC}/pull/30`, `${BENCH}/pull/47`, `${SRC}/blob/main/singleton/bn254/genpow-reconstructed/README.md`],
  },
  'bch-groth16-bls12381-singleton-genpow': {
    status: 'reviewed',
    reason: 'Independent review 2026-10-26/27 of the corrected 5,675 B program (sha 6b36b9fe…): canonical decoders with exact curve residuals, complete group operations, and on-chain r-component projection of every G1/G2 pairing operand. Cofactor-equivalent domain: soundness holds by an endpoint argument, but A, B and C are malleable by cofactor torsion and a non-subgroup B is not rejected. Native resource HOLD (op-cost).',
    refs: [...FINDINGS, `${SRC}/pull/31`, `${BENCH}/pull/48`, `${SRC}/blob/main/singleton/bls12-381/leader-recovered/README.md`],
  },

  // minop singletons: two independent reviews 2026-10-27 (notes: verifier.cash work/review-minop-1, -2/NOTES.md);
  // documentation follow-ups only (comments, README soundness sections), no status impact.
  'bch-groth16-singleton-minop': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: the 50,539 B locking recompiles byte-identically; inputs < r via GLV k >= 0, B in G2 by the exact (6x+2)+psi-psi^2+psi^3 endpoint relation, r | lambda for the residue exponent; no owner gap. Doc follow-ups only.',
    refs: [`${SRC}/blob/main/singleton/bn254/README.md`],
  },
  'bch-groth16-bls12381-singleton-minop': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: the 58,007 B locking regenerates and recompiles byte-identically; inputs < r, complete jacAddG1, B in G2 by psi(B)=[x]B, r | (p+|x|); A/C on-curve only (cofactor malleability only, documented). Doc follow-ups only.',
    refs: [`${SRC}/blob/main/singleton/bls12-381/README.md`],
  },

  // BLS12-381 FS singletons: two independent reviews 2026-10-27 (notes: verifier.cash work/review-bls-fs-singletons-1, -2/).
  // All hold under the disclosed FS-PIT (SHA-256 random-oracle) model with cofactor-equivalent A/C.
  'bch-groth16-bls12381-singleton-fs': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: 53,825 B locking rebuilt byte-exact; FS-PIT transcript, exact B twist/psi subgroup walk, A/C curve checks, inputs < r and the Merkle-authenticated GT table hold under the SHA-256 random-oracle model (A/C cofactor malleability only). Bound: groth16_cashscript chunked/bls12-381/README.md section 5 with the singleton\'s numbers, (23*q_beta + 160*q_alpha)/2^256 + 3*N(N-1)/2^257 (same 24 relations, degrees 23/137, q132 quotient; N = q + fewer than 2^22 setup hashes; 1,104 verifier SHA-256 per spend).',
    refs: [`${SRC}/blob/main/singleton/bls12-381/README.md`],
  },
  'bch-groth16-bls12381-singleton-fs-spec': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: 47,879 B P2SH32 redeem rebuilt byte-exact; same owner map as singleton-fs, with the delta lines rebuilt in-script from baked constants by exact affine equations (random-oracle model).',
    refs: [`${SRC}/blob/main/singleton/bls12-381/README.md`],
  },
  'bch-groth16-bls12381-singleton-fs-spec-shared': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: 23,460 B redeem rebuilt byte-exact; the shared authenticatePic and regular bodies keep index, window and root as call-site constants and pass all chained state as parameters (random-oracle model).',
    refs: [`${SRC}/blob/main/singleton/bls12-381/README.md`],
  },
  'bch-groth16-bls12381-singleton-fs-spec-zero': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: 23,784 B redeem rebuilt byte-exact; the zero-PIC codec only changes the wire encoding (expanded from committed bytes, full consumption required); A, B and C are uncompressed and checked (random-oracle model).',
    refs: [`${SRC}/blob/main/singleton/bls12-381/README.md`],
  },

  // BLS12-381 intratx-fs family (13 ids): three-lens review 2026-10-27 (notes: verifier.cash work/review-bls-fs-1..3/),
  // then the FS-PIT soundness argument was written in chunked/bls12-381/README.md and signed off by two
  // reviews 2026-10-27 (groth16_cashscript 9e56c4f, bench cef15cd; notes: verifier.cash work/fs-pit/).
  'bch-groth16-bls12381-intratx-fs': {
    status: 'reviewed',
    reason: 'FS-PIT soundness argument, groth16_cashscript chunked/bls12-381/README.md sections 1-6 (two reviews signed off 2026-10-27). Sound in the SHA-256 random-oracle model with bound (23*q_beta + 160*q_alpha)/2^256 + 3*N(N-1)/2^257 (README section 5: q counts adversary and verifier SHA-256 queries, q_beta/q_alpha the challenge queries among them, N = q + fewer than 2^22 + 2^7 setup hashes). B is checked in G2; A and C are on-curve and cofactor-equivalent (disclosed). The PIC helper is imported before the binder; this rests on the accepted fail-closed argument in section 6.',
    refs: [`${SRC}/blob/main/chunked/bls12-381/README.md`],
  },
  ...Object.fromEntries(
    (
      [
        ['bch-groth16-bls12381-intratx-fs-compact', FS_PIT + FS_FAIL_CLOSED + FS_REBUILD],
        ['bch-groth16-bls12381-intratx-fs-fused-final', FS_PIT + FS_FAIL_CLOSED + FS_REBUILD],
        ...[
          'bch-groth16-bls12381-intratx-fs-fused-regular',
          'bch-groth16-bls12381-intratx-fs-fused-regular-pairs',
          'bch-groth16-bls12381-intratx-fs-fused-regular-pairs-packed',
          'bch-groth16-bls12381-intratx-fs-fused-regular-triples',
          'bch-groth16-bls12381-intratx-fs-fused-carrier-pair',
          'bch-groth16-bls12381-intratx-fs-fused-middle-pair',
          'bch-groth16-bls12381-intratx-fs-fused-first-tail',
          'bch-groth16-bls12381-intratx-fs-regular-initializer',
        ].map((id) => [id, FS_PIT + FS_FAIL_CLOSED]),
        ['bch-groth16-bls12381-intratx-fs-fused-coordinator-head', FS_PIT + FS_BINDER_FIRST],
        ['bch-groth16-bls12381-intratx-fs-fused-coordinator-head-fields', FS_PIT + FS_BINDER_FIRST],
      ] as [string, string][]
    ).map(([id, reason]): [string, ReviewStatus] => [id, { status: 'reviewed', reason, refs: [`${SRC}/blob/main/chunked/bls12-381/README.md`] }]),
  ),

  // residue family: two independent reviews 2026-10-27 (notes: verifier.cash work/review-residue-1, -2/).
  'bch-groth16-intratx-residue': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: vectors regenerate byte-identically; exact frames on all 11 inputs, count/index and successor pins, inputs < r, exact G2 endpoint test and quotient-torus terminal with r | lambda. Nit: in0=0 has a negative-zero encoding (malleability only).',
    refs: [`${SRC}/blob/main/chunked/intratx/README.md`],
  },
  'bch-groth16-intratx-residue-large': {
    status: 'reviewed',
    reason: 'Two independent reviews 2026-10-27: vectors regenerate byte-identically; same Miller/torus/endpoint kernels as intratx-residue with a 4-input root, position gates, exact frames and sha256 successor pins; the mixed add has an equal-point branch.',
    refs: [`${SRC}/blob/main/chunked/intratx/README.md`],
  },
  // covenant-residue: review 2026-10-27, then the composition argument, deployment premises P1/P2 and the
  // statement locator were written down and the reviewer signed off (groth16_cashscript 76a30ce, bench c0ce30e;
  // notes: verifier.cash work/covenant-residue/).
  'bch-groth16-chunked-covenant-residue': {
    status: 'reviewed',
    reason: 'The reviewer signed off once B1 was fixed, and B1 is now fixed. Every value the verdict depends on has an owner across the 12-transaction graph: one input per step, fixed-width hash256 state commitments, a pinned successor locking, and an immutable terminal verdict. This rests on two deployment premises. P1: the category genesis spends an outpoint with output index 0, creates no NFT of C except minting batons at L_0, and the graph is regenerated with the real C (the bench uses the placeholder 0xcd..cd). P2: the verdict is an unspendable, empty-commitment immutable NFT that an off-chain consumer reads through its unique one-input ancestry; the statement is in0 (push 6) and in1 (push 5) of the genesis unlocking. A consumer that checks every spent locking does not need P1.',
    refs: [`${SRC}/blob/main/chunked/pairing/README.md#covenant-residue-composition-what-the-scripts-enforce-and-what-the-deployment-supplies`],
  },
  'bch-groth16-bls12381-chunked-covenant-residue': {
    status: 'reviewed',
    reason: 'Same composition argument as BN254, over 27 single-input transactions with 48-byte limbs. All 17 isolated invalid-input runs are loaded and rejected. Premises: P1, the category genesis creates only L_0 minting batons and the graph is regenerated with the real C (the bench uses the placeholder 0xbe..be), with an index-0 outpoint. P2, an off-chain consumer reads the unspendable empty-commitment verdict through its one-input ancestry, and the statement is in0 (push 6) and in1 (push 5) of the genesis unlocking.',
    refs: [`${SRC}/blob/main/chunked/bls12-381/README.md#covenant-residue-composition-and-deployment-premises`],
  },

  // no public source: unreviewed until the author (toorik2) shares the generator source
  ...Object.fromEntries(
    ['bch-groth16-intratx-crown8-rawchain', 'bch-groth16-intratx-direct-state-public', 'bch-groth16-intratx-general'].map(
      (id): [string, ReviewStatus] => [id, { status: 'unreviewed', reason: 'No source: the generator source is not public, so the shipped bytes cannot be reviewed; source requested from the author.' }],
    ),
  ),

  // baselines: third-party reference verifiers (nChain sCrypt, sCrypt bn256), measured for comparison only
  'nchain': baseline,
  'scrypt-bn256': baseline,

  // demo: harness self-test, not a verifier
  'bch-multistep-demo': { status: 'demo', reason: 'Harness self-test (multi-step covenant demo), not a Groth16 verifier.' },

  // components: partial pairing / vk_x checkpoints (category 'partial'), not full verifiers
  'bch-vkx-singleton': component,
  'bch-vkx-bls12381-singleton': component,
  'bch-vkx-chunked-twoloop': component,
  'bch-vkx-chunked-shamir': component,
  'bch-vkx-chunked-covenant': component,
  'bch-pairing-singleton': component,
  'bch-pairing-bls12381-singleton': component,
  'bch-pairing-chunked': component,
  'bch-pairing-bls12381-chunked': component,
  'bch-pairing-bls12381-intratx': component,

  // archived: legacy large chains, superseded by the reviewed sound-native / SI-GLS builds; kept as history, not ranked
  'bch-groth16-chunked': archived,
  'bch-groth16-chunked-covenant': archived,
  'bch-groth16-bls12381-intratx': archived,
  'bch-groth16-bls12381-grouped': archived,
  'bch-groth16-bls12381-chunked': archived,
  'bch-groth16-bls12381-chunked-covenant': archived,
};

export const reviewStatusOf = (impl: Pick<Implementation, 'id' | 'reviewStatus'>): ReviewStatus =>
  impl.reviewStatus ?? REVIEW_STATUS[impl.id] ?? DEFAULT_REVIEW_STATUS;
