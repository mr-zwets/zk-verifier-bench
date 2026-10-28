// The measured row of one results.json entry: entryOf turns a BenchmarkResult into the row the
// website renders (category, score, bch / correctness / generality / packaging cells, ...).
// Split out of export-json.ts because this file is part of the harness fingerprint that every
// row's inputHash includes (input-hash.ts): an edit here changes rows, so it must re-run them.
// export-json.ts keeps only the planning, frontier and history logic, which is recomputed from
// the rows on every export and so is not a row input.
import { reviewStatusOf } from './review-status.js';
import type { BenchmarkResult, Implementation } from './types.js';
import { STANDARD_UNLOCKING_CAP, SPEC_SCRIPT_SIZE_CAP, realOpCostBudget, specOpCostBudget } from './vm.js';
import { txv5Summary } from './txv5.js';

export const SIZE_CAP = STANDARD_UNLOCKING_CAP; // 10,000 B per locking/unlocking script

// 'spec' = a full verifier that targets the PROPOSED bch-spec upgrade (100 kB scripts), NOT
// current BCH. It gets its own category so it is not ranked on the current-BCH 'full' leaderboard
// / frontier (a spec entry plays by different consensus limits — an apples-to-oranges comparison).
export type Category = 'full' | 'spec' | 'partial' | 'demo';


export const categoryOf = (r: BenchmarkResult): Category => {
  if (r.impl.demo === true) return 'demo';
  if (r.impl.vm === 'bch-spec') return 'spec'; // proposed-upgrade verifier, its own leaderboard
  return r.impl.proofSystem === 'Groth16' ? 'full' : 'partial';
};

// The real BCH blockers, computed independently (the benchmark records only the
// FIRST failing reason, but nchain/scrypt trip both walls). script-size: any
// step's locking OR unlocking exceeds the 10,000-byte cap. op-cost: the heaviest
// step needs more than one standard input's budget.
export const bchCell = (r: BenchmarkResult) => {
  // A bch-spec entry is graded against the 100 kB spec cap; a current-BCH entry against 10 kB.
  const sizeCap = r.impl.vm === 'bch-spec' ? SPEC_SCRIPT_SIZE_CAP : SIZE_CAP;
  const scriptSize = r.steps.some((s) => s.lockingBytes > sizeCap || s.unlockingBytes > sizeCap);
  const opCost = r.inputsForHeaviestStep > 1;
  const blockers = [...(scriptSize ? ['script-size'] : []), ...(opCost ? ['op-cost'] : [])];
  const overByBytes = r.steps.filter((s) => s.lockingBytes > sizeCap || s.unlockingBytes > sizeCap).length;
  const detail = r.bchCompatible
    ? r.impl.vm === 'bch-spec'
      ? 'every step fits the proposed bch-spec per-tx limits (100 kB scripts) — NOT current BCH'
      : 'every step fits BCH per-tx limits'
    : [
        scriptSize ? `${overByBytes}/${r.stepCount} step(s) over the ${sizeCap.toLocaleString('en-US')} B script cap` : null,
        opCost ? `heaviest step ~${r.inputsForHeaviestStep}× one input's op-cost budget` : null,
      ]
        .filter(Boolean)
        .join('; ');
  // standardness is strictly stronger than consensus compatibility: a consensus-valid
  // verifier can still be non-standard (e.g. an intra-tx bundle is one ~626 KB tx, over
  // the 100 KB standard size, so it must be mined directly rather than relayed).
  const standard = {
    fits: r.fitsBchStandardness,
    detail: r.fitsBchStandardness ? 'relayable under standard mempool policy' : r.bchStandardnessReason ?? 'non-standard',
  };
  return { compatible: r.bchCompatible, blockers, detail, standard };
};

export const isBsvSeed = (impl: Implementation): boolean =>
  impl.reference === true || /BSV mainnet/.test(impl.source);
// BSV prior art: a single huge transaction that is correct but does not fit BCH.
// Only the seeded BSV verifiers carry this framing (not BCH-native sub-steps).
export const isBsvSingleton = (impl: Implementation, validPassed: boolean, bchCompatible: boolean): boolean =>
  isBsvSeed(impl) && impl.structure === 'single-tx' && validPassed && !bchCompatible;

// Fixture outcomes for the entry; mathematical soundness is a separate review.
// Mirrors the harness `pass` gate and preserves the reasons for failed or missing evidence:
//   'fail'       - a hard defect: the valid run is not fully accepted, an invalid run is wrongly
//                  accepted, the worst-case proof is rejected, packaging is insecure, or a
//                  cross-stage staple or a maintainer red-team attack is accepted. `failures` names
//                  each. DISQUALIFIED — excluded from the frontier leaders and score-history.
//   'valid-only' - the valid run passes but required fixture evidence is missing.
//   'pass'       - all supplied honest runs accepted and required fixture gates completed.
export const correctnessOf = (r: BenchmarkResult) => {
  const csb = r.crossStageBinding;
  const failures = [
    !r.validPassed ? 'valid run not fully accepted' : null,
    r.invalidTotal > 0 && r.invalidRejected < r.invalidTotal
      ? `${r.invalidTotal - r.invalidRejected}/${r.invalidTotal} invalid run(s) wrongly accepted`
      : null,
    r.proofsPassed < r.proofsTested ? `${r.proofsTested - r.proofsPassed}/${r.proofsTested} honest run(s) rejected (completeness)` : null,
    r.worstCase?.accepted === false ? 'worst-case proof rejected (completeness)' : null,
    csb.unboundSeams > 0
      ? `cross-stage staple accepted (${csb.unboundSeams}/${csb.seamsTested} seam(s))`
      : null,
    !r.securePackaging ? 'insecure P2SH20 packaging' : null,
    r.publicInputs.accepted > 0
      ? `mutated public inputs accepted (${r.publicInputs.accepted}/${r.publicInputs.tested}; first: ${r.publicInputs.firstAccepted})`
      : null,
    r.redTeam.accepted > 0
      ? `maintainer red-team attack accepted (${r.redTeam.accepted}/${r.redTeam.tested}; first: "${r.redTeam.firstAccepted}")`
      : null,
  ].filter((x): x is string => x !== null);
  const verdict: 'pass' | 'fail' | 'valid-only' =
    failures.length > 0 ? 'fail' : r.pass ? 'pass' : 'valid-only';
  return {
    verdict,
    validAccepted: r.validPassed,
    invalid: { tested: r.invalidTotal, rejected: r.invalidRejected },
    worstCaseAccepted: r.worstCase?.accepted ?? null,
    // Cross-stage stapling (multi-stage soundness): can one proof's stage be spliced onto another
    // proof's remaining stages inside one transaction? A verifier that binds every stage to one
    // proof rejects every such hybrid; an accepted hybrid is a soundness hole (a stage output that
    // nothing later ties to the proof the rest of the run consumes). Tested by building hybrid runs
    // from two distinct valid proofs at each seam (benchmark.ts crossStageStaple). bound=false is a
    // `fail`; bound=null means N/A or untested (reason retained), never positive evidence.
    crossStageBinding: {
      applicable: csb.applicable,
      bound: csb.applicable && csb.seamsTested > 0 ? csb.unboundSeams === 0 : null,
      ...(csb.reason ? { reason: csb.reason } : {}),
      seamsTested: csb.seamsTested,
      unboundSeams: csb.unboundSeams,
      ...(csb.firstUnboundSeam ? { firstUnboundSeam: csb.firstUnboundSeam } : {}),
      detail: csb.reason ?? (!csb.applicable
        ? 'not staple-tested — single-tx, or a covenant/grouped token hand-off the harness does not model yet'
        : csb.unboundSeams === 0
          ? `${csb.seamsTested} sampled seams rejected with a qualified second proof (finite fixture evidence only)`
          : `UNBOUND: ${csb.unboundSeams}/${csb.seamsTested} seam(s) accept a spliced 2-proof hybrid (first at "${csb.firstUnboundSeam}") — one proof's stage can be stapled onto another proof's remaining stages`),
    },
    // Maintainer red-team gate (harness/redteam.ts): attacks on the entry's exact bytes that a
    // sound verifier must reject, e.g. a real proof with FORGED public inputs. null = no file.
    redTeam: r.redTeam.present
      ? { stale: r.redTeam.stale, tested: r.redTeam.tested, accepted: r.redTeam.accepted, kinds: r.redTeam.kinds, ...(r.redTeam.firstAccepted ? { firstAccepted: r.redTeam.firstAccepted } : {}) }
      : null,
    // Public-input binding gate (harness/gates.ts); null = the entry did not declare its inputs.
    publicInputs: r.publicInputs.declared ? { tested: r.publicInputs.tested, accepted: r.publicInputs.accepted, ...(r.publicInputs.firstAccepted ? { firstAccepted: r.publicInputs.firstAccepted } : {}) } : null,
    // Layout review (not a verdict): free-length pads whose lengthening breaks a sibling input.
    layoutReview: r.layout.applicable ? { padsTested: r.layout.padsTested, freeLength: r.layout.malleable, dependencies: r.layout.dependencies } : null,
    failures,
  };
};

export const entryOf = (r: BenchmarkResult) => ({
  id: r.impl.id,
  name: r.impl.name,
  category: categoryOf(r),
  official: isBsvSeed(r.impl), // seeded baseline, not a community submission
  solver: isBsvSeed(r.impl) ? { handle: r.impl.id, model: null, official: true } : null,
  curve: r.impl.field,
  structure: r.impl.structure,
  proofSystem: r.impl.proofSystem,
  // Which BCH VM the entry targets: 'bch-2026' (current chain) or 'bch-spec' (proposed 100 kB-
  // script upgrade). Lets the site badge/segregate spec entries (also carried by `category: spec`).
  vmTarget: r.impl.vm ?? 'bch-2026',
  // Rolled-up fixture outcomes: verdict (pass | fail | valid-only), the underlying valid/invalid-run and
  // worst-case data, the folded-in cross-stage stapling result, and a `failures` summary. The
  // finite-run headline; it does not establish universal verifier correctness;
  // `verdict: 'fail'` disqualifies the entry from the frontier leaders / score-history (see main()).
  correctness: correctnessOf(r),
  // Evidence-based soundness review status: 'reviewed' (independent review of this exact
  // artifact), 'unreviewed' (author/maintainer claim, no open finding; the default) or
  // 'withdrawn' (claim withdrawn or a finding applies; the implementation is normally removed
  // from REGISTRY, so its row leaves this list), 'baseline' / 'demo' / 'component' (labels for
  // references, the self-test and partial checkpoints) or 'archived' (superseded; the row stays
  // listed). Withdrawn and archived entries are excluded from the frontier leader / current and
  // new history points (see main()); their old history points stay in the file.
  reviewStatus: reviewStatusOf(r.impl),
  // headline score = full on-chain footprint (lower is better): the verifier scripts PLUS
  // the serialized transaction overhead (envelope + outpoints + CashToken prefixes + varints).
  // Folding tx overhead in makes structures comparable — a covenant chain pays it once PER
  // STEP (its real recurring cost), a single-tx verifier pays it once. `size` breaks it down.
  score: r.totalBytes + r.totalTxOverheadBytes,
  size: {
    scriptBytes: r.totalBytes,
    txOverheadBytes: r.totalTxOverheadBytes,
    transactions: r.txCount,
    total: r.totalBytes + r.totalTxOverheadBytes,
  },
  // dead-weight zero-padding: all-zero push bytes added to unlockings purely to buy op-cost
  // budget (wherever they sit — last in bare scripts, second-to-last under P2SH), and their
  // share of the SCRIPT bytes. A big slice of the chunking overhead; 0 for unpadded singletons
  // (proof in the witness, no covenant padding).
  padding: { bytes: r.totalPadBytes, fraction: r.totalBytes > 0 ? r.totalPadBytes / r.totalBytes : 0 },
  // op-cost benchmarks, keyed by the PROOF SCENARIO actually RUN. Even though the
  // chunked covenant lockings are now worst-case SIZED (the fixed step graph can
  // verify ANY public input < r), the measured op-cost still depends on the specific
  // proof executed: a sparse/small input skips most doublings+adds, a dense full-width
  // input pays for all of them. So one number is misleading — we key by the proof run.
  // 'smallProof' is the committed small public inputs the vectors ship with; a
  // 'worstCase' run (dense, near-r inputs through the SAME lockings) is added per entry
  // as those vectors land. NOTE: any GLV/Shamir vk_x verifier is proof-DEPENDENT (the MSM
  // does an add nearly every iteration for dense scalars), so its worstCase jumps ~15M over
  // smallProof — this holds for the GLV singletons too, not just the chunked entries. Every
  // runtime-general entry should therefore ship a worstCaseProof so the column is apples-to-
  // apples; measuring one entry on committed and another on worst-case is the mismatch that
  // makes a singleton look cheaper than an equivalent chunked build when it is not.
  benchmarks: {
    smallProof: {
      opCost: r.totalOperationCost,
      steps: r.stepCount,
      heaviestStepOpCost: r.maxStepOperationCost,
      inputsForHeaviestStep: r.inputsForHeaviestStep,
    },
    ...(r.worstCase
      ? {
          worstCase: {
            accepted: r.worstCase.accepted,
            opCost: r.worstCase.totalOperationCost,
            steps: r.worstCase.stepCount,
            heaviestStepOpCost: r.worstCase.maxStepOperationCost,
            inputsForHeaviestStep: r.worstCase.inputsForHeaviestStep,
          },
        }
      : {}),
  },
  // Total op-cost budget these deployed contracts actually hold: the sum over inputs of
  // (densityControlBase + this input's unlocking bytecode length) * 800 — base 41 on the
  // current BCH_2026 VM, 10,000 on bch-spec. Uses each input's REAL unlocking length (redeem
  // script + unlocking script, incl. any op-cost padding; not the script-size cap), so it is
  // the true ceiling the total op-cost is measured against. Proof-independent, so it sits
  // outside `benchmarks`.
  opCostBudget: r.steps.reduce(
    (a, s) => a + (r.impl.vm === 'bch-spec' ? specOpCostBudget : realOpCostBudget)(s.unlockingBytes),
    0,
  ),
  // BSV prior art: a single huge transaction that is correct but does not fit BCH.
  bsvSingleton: isBsvSingleton(r.impl, r.validPassed, r.bchCompatible),
  // correctness was judged under BSV's post-Genesis OP_RETURN-terminator rule, which
  // BCH treats as failure (so the success case is scored differently per chain)
  bsvOpReturn: r.bsvOpReturn,
  bch: bchCell(r),
  // Binding is declared; same-program shape and declared proof components are checked.
  generality: {
    binding: r.proofBinding,
    runtimeGeneral: r.runtimeGeneral,
    proofsTested: r.proofsTested,
    proofsPassed: r.proofsPassed,
    proofIdentity: r.proofIdentity,
    detail: r.proofBinding === 'baked'
      ? 'instance-specific: proof binding declared baked'
      : `${r.runtimeGeneral ? 'distinct-proof fixtures accepted' : 'NOT DEMONSTRATED'}: ${r.proofsPassed}/${r.proofsTested} supplied runs accepted; ${r.proofIdentity.reason ?? 'declared proof components differ (finite fixture evidence only)'}`,
  },
  // token-threading covenant safety (only meaningful for covenant entries): does the
  // covenant pin the carried token (category continuity + capability) so the threaded
  // state cannot be swapped/forged? null when the entry does not thread a token.
  tokenSafety: r.tokenThreaded
    ? {
        threaded: true,
        enforced: r.tokenSafetyEnforced === true,
        detail:
          r.tokenSafetyEnforced === true
            ? 'covenant pins category + capability and perpetuates the commitment'
            : 'state threaded through the NFT commitment, but category continuity / capability are NOT enforced — a real deployment must pin a fixed category with a perpetuated mutable commitment (or mint a fresh immutable token each step)',
      }
    : null,
  // Whole-run rejection is an observation, not attribution to a domain predicate.
  inputValidation: {
    ...r.inputValidation,
    detail: `NOT DEMONSTRATED: ${r.inputValidation.rejected}/${r.inputValidation.tested} supplied runs rejected; ${r.inputValidation.reason}`,
  },
  // envelope security: `type` is what the steps' lockings actually are (p2sh32 | p2s |
  // p2sh20 | mixed). A contract hidden behind an insecure P2SH20 hash (OP_HASH160,
  // ~2^80 collision security) is DISALLOWED — it must use P2SH32, or deploy bare (P2S).
  // `secure: false` disqualifies the entry (it is excluded from the frontier leaders and
  // the score-history below). Orthogonal to BCH compatibility: P2SH20 is itself valid +
  // relayable, this is the competition's cryptographic-security rule.
  packaging: {
    secure: r.securePackaging,
    type: r.packagingType,
    ...(r.securePackaging ? {} : { detail: `DISALLOWED: ${r.insecurePackagingReason}` }),
  },
  // bch-spec entries only (null otherwise): the TXv5-as-written grade (bench issue #35). BCH_SPEC
  // gives each input (10,000 + len) * 800 op-cost; TXv5 as written keeps the density base at 41,
  // so (41 + len) * 800. Records whether the shipped tx validates on that VM (consensus /
  // standard) and, if not, the minimal zero padding (lengthening the entry's existing pad push,
  // or inserting one where the scripts ignore it) and the padded score; an entry that pins its
  // push layout is 'not-paddable' with an estimate only. Every honest run is graded (`honest`);
  // `summary` is the figure the site shows (fixture 0, the TXv5 worst case, standard only if
  // every honest run's figure is standard).
  txv5: r.txv5 ? { summary: txv5Summary(r.txv5, r.totalBytes + r.totalTxOverheadBytes), ...r.txv5 } : null,
  source: r.impl.source,
});

// `inputHash` (harness/input-hash.ts) is appended to every row: the hash of the inputs that
// produced its measurements. The incremental export re-runs a row only when it changes.
export type Entry = ReturnType<typeof entryOf> & { inputHash?: string; stale?: string };
