import { decodeAuthenticationInstructions, vmNumberToBigInt } from '@bitauth/libauth';

import type { BenchmarkResult, Implementation, ProofInput, Scenario, Step } from './types.js';
type ContextKind = 'bare' | 'covenant' | 'intraTx' | 'grouped';
type InputBytes = { lockingBytecode: Uint8Array; unlockingBytecode: Uint8Array };
type GroupedContext = NonNullable<Step['grouped']>;

const OP_RETURN = Uint8Array.of(0x6a);

const isBytes = (value: unknown): value is Uint8Array => value instanceof Uint8Array;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const bytesHex = (value: Uint8Array): string => Buffer.from(value).toString('hex');

const stepName = (step: Step, index: number): string =>
  typeof step.label === 'string' && step.label.length > 0 ? step.label : `step ${index}`;

const failStep = (runLabel: string, step: Step, index: number, reason: string): never => {
  throw new Error(`${runLabel} step ${index} (${stepName(step, index)}): ${reason}`);
};

const failRun = (runLabel: string, reason: string): never => {
  throw new Error(`${runLabel}: ${reason}`);
};

const contextKind = (step: Step, runLabel: string, index: number): ContextKind => {
  const present: ContextKind[] = [];
  if (step.covenant !== undefined) present.push('covenant');
  if (step.intraTx !== undefined) present.push('intraTx');
  if (step.grouped !== undefined) present.push('grouped');
  if (present.length > 1) failStep(runLabel, step, index, `has incompatible contexts ${present.join(', ')}`);
  return present[0] ?? 'bare';
};

const assertInputBytes = (input: InputBytes, runLabel: string, step: Step, index: number, where: string): void => {
  if (!isBytes(input.lockingBytecode) || !isBytes(input.unlockingBytecode)) {
    failStep(runLabel, step, index, `${where} must contain byte-array locking and unlocking scripts`);
  }
};

const assertCapability = (value: unknown, runLabel: string, step: Step, index: number, where: string): void => {
  if (value !== 'none' && value !== 'mutable' && value !== 'minting') {
    failStep(runLabel, step, index, `${where} has invalid capability`);
  }
};

const assertToken = (
  value: { capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array } | undefined,
  runLabel: string,
  step: Step,
  index: number,
  where: string,
): void => {
  if (value === undefined) return;
  assertCapability(value.capability, runLabel, step, index, where);
  if (!isBytes(value.commitment)) failStep(runLabel, step, index, `${where}.commitment must be a byte array`);
};

const assertCovenant = (step: Step, runLabel: string, index: number): void => {
  const covenant = step.covenant!;
  if (!isBytes(covenant.category)) failStep(runLabel, step, index, 'covenant.category must be a byte array');
  assertCapability(covenant.capability, runLabel, step, index, 'covenant');
  if (!isBytes(covenant.inCommitment)) failStep(runLabel, step, index, 'covenant.inCommitment must be a byte array');
  if (!isBytes(covenant.outCommitment)) failStep(runLabel, step, index, 'covenant.outCommitment must be a byte array');
  if (!isBytes(covenant.outLockingBytecode)) failStep(runLabel, step, index, 'covenant.outLockingBytecode must be a byte array');
  if (covenant.inputCapability !== undefined) {
    assertCapability(covenant.inputCapability, runLabel, step, index, 'covenant.inputCapability');
  }
  if (covenant.secondOutputBaton !== undefined && typeof covenant.secondOutputBaton !== 'boolean') {
    failStep(runLabel, step, index, 'covenant.secondOutputBaton must be boolean');
  }
};

const sameToken = (
  left: GroupedContext['inToken'],
  right: GroupedContext['inToken'],
): boolean => {
  if (left === undefined || right === undefined) return left === right;
  return left.capability === right.capability && bytesEqual(left.commitment, right.commitment);
};

const effectiveInputToken = (grouped: GroupedContext, inputIndex: number): GroupedContext['inToken'] =>
  grouped.inputTokens?.[inputIndex] ?? (inputIndex === 0 ? grouped.inToken : undefined);

const effectiveOutputLocking = (grouped: GroupedContext): Uint8Array =>
  grouped.outToken === undefined ? OP_RETURN : grouped.outLockingBytecode ?? OP_RETURN;

const assertGrouped = (run: Step[], runLabel: string): void => {
  const groups = new Map<number, number[]>();
  let previousGroup = -1;
  run.forEach((step, index) => {
    const grouped = step.grouped!;
    if (!Number.isInteger(grouped.group) || grouped.group < 0) failStep(runLabel, step, index, 'grouped.group must be a non-negative integer');
    if (!Number.isInteger(grouped.index) || grouped.index < 0) failStep(runLabel, step, index, 'grouped.index must be a non-negative integer');
    if (grouped.group < previousGroup) failStep(runLabel, step, index, 'grouped groups must be ordered');
    previousGroup = grouped.group;
    if (!isBytes(grouped.category)) failStep(runLabel, step, index, 'grouped.category must be a byte array');
    if (!Array.isArray(grouped.inputs)) failStep(runLabel, step, index, 'grouped.inputs must be an array');
    grouped.inputs.forEach((input, inputIndex) => assertInputBytes(input, runLabel, step, index, `grouped.inputs[${inputIndex}]`));
    if (grouped.inputTokens !== undefined) {
      if (!Array.isArray(grouped.inputTokens) || grouped.inputTokens.length !== grouped.inputs.length) {
        failStep(runLabel, step, index, 'grouped.inputTokens must match grouped.inputs length');
      }
      grouped.inputTokens.forEach((token, inputIndex) => {
        assertToken(token, runLabel, step, index, `grouped.inputTokens[${inputIndex}]`);
      });
    }
    assertToken(grouped.inToken, runLabel, step, index, 'grouped.inToken');
    assertToken(grouped.outToken, runLabel, step, index, 'grouped.outToken');
    if (grouped.outLockingBytecode !== undefined && !isBytes(grouped.outLockingBytecode)) {
      failStep(runLabel, step, index, 'grouped.outLockingBytecode must be a byte array');
    }
    const indices = groups.get(grouped.group) ?? [];
    indices.push(index);
    groups.set(grouped.group, indices);
  });

  const groupIds = [...groups.keys()];
  groupIds.forEach((group, ordinal) => {
    if (group !== ordinal) failRun(runLabel, `group ${group} is not contiguous in the topology`);
    const indices = groups.get(group)!;
    const first = indices[0]!;
    const last = indices[indices.length - 1]!;
    if (last - first + 1 !== indices.length) failRun(runLabel, `group ${group} is not a contiguous subrun`);
    indices.forEach((runIndex, localIndex) => {
      const step = run[runIndex]!;
      const grouped = step.grouped!;
      if (grouped.index !== localIndex) failStep(runLabel, step, runIndex, `grouped.index must be ${localIndex}`);
      if (grouped.inputs.length !== indices.length) failStep(runLabel, step, runIndex, `grouped.inputs must contain ${indices.length} inputs`);
      grouped.inputs.forEach((input, inputIndex) => {
        const actual = run[indices[inputIndex]!]!;
        if (!bytesEqual(input.lockingBytecode, actual.lockingBytecode)) {
          failStep(runLabel, step, runIndex, `grouped.inputs[${inputIndex}].lockingBytecode does not match the actual subrun`);
        }
        if (!bytesEqual(input.unlockingBytecode, actual.unlockingBytecode)) {
          failStep(runLabel, step, runIndex, `grouped.inputs[${inputIndex}].unlockingBytecode does not match the actual subrun`);
        }
      });
    });

    const reference = run[first]!.grouped!;
    indices.forEach((runIndex) => {
      const step = run[runIndex]!;
      const grouped = step.grouped!;
      if (!bytesEqual(grouped.category, reference.category)) {
        failStep(runLabel, step, runIndex, 'grouped.category differs from group context');
      }
      grouped.inputs.forEach((_, inputIndex) => {
        if (!sameToken(effectiveInputToken(grouped, inputIndex), effectiveInputToken(reference, inputIndex))) {
          failStep(runLabel, step, runIndex, `grouped.inputTokens[${inputIndex}] differs from group context`);
        }
      });
      if (!sameToken(grouped.outToken, reference.outToken)) {
        failStep(runLabel, step, runIndex, 'grouped.outToken differs from group context');
      }
      if (!bytesEqual(effectiveOutputLocking(grouped), effectiveOutputLocking(reference))) {
        failStep(runLabel, step, runIndex, 'grouped output locking differs from group context');
      }
    });
  });
};

const assertIntraTx = (run: Step[], runLabel: string): void => {
  run.forEach((step, index) => {
    const intraTx = step.intraTx!;
    if (!Number.isInteger(intraTx.index) || intraTx.index !== index) {
      failStep(runLabel, step, index, `intraTx.index must be ${index}`);
    }
    if (!Array.isArray(intraTx.inputs) || intraTx.inputs.length !== run.length) {
      failStep(runLabel, step, index, `intraTx.inputs must contain ${run.length} inputs`);
    }
    intraTx.inputs.forEach((input, inputIndex) => {
      assertInputBytes(input, runLabel, step, index, `intraTx.inputs[${inputIndex}]`);
      const actual = run[inputIndex]!;
      if (!bytesEqual(input.lockingBytecode, actual.lockingBytecode)) {
        failStep(runLabel, step, index, `intraTx.inputs[${inputIndex}].lockingBytecode does not match the actual run`);
      }
      if (!bytesEqual(input.unlockingBytecode, actual.unlockingBytecode)) {
        failStep(runLabel, step, index, `intraTx.inputs[${inputIndex}].unlockingBytecode does not match the actual run`);
      }
    });
  });
};

/** Validate a run's executable shape without evaluating it in a VM. */
export const assertRunShape = (run: Step[], label: string): void => {
  if (!Array.isArray(run) || run.length === 0) failRun(label, 'run must be non-empty');
  const kinds = run.map((step, index) => {
    if (step === undefined || step === null || typeof step !== 'object') failRun(label, `step ${index} is not an object`);
    if (!isBytes(step.lockingBytecode) || !isBytes(step.unlockingBytecode)) {
      failStep(label, step, index, 'lockingBytecode and unlockingBytecode must be byte arrays');
    }
    return contextKind(step, label, index);
  });
  const kind = kinds[0]!;
  kinds.forEach((other, index) => {
    if (other !== kind) failStep(label, run[index]!, index, `context kind ${other} differs from ${kind}`);
  });
  if (kind === 'covenant') run.forEach((step, index) => assertCovenant(step, label, index));
  if (kind === 'intraTx') assertIntraTx(run, label);
  if (kind === 'grouped') assertGrouped(run, label);
};

const compareInputLockings = (left: InputBytes[], right: InputBytes[], runLabel: string, step: Step, index: number, where: string): void => {
  if (left.length !== right.length) failStep(runLabel, step, index, `${where} topology differs in input count`);
  left.forEach((input, inputIndex) => {
    if (!bytesEqual(input.lockingBytecode, right[inputIndex]!.lockingBytecode)) {
      failStep(runLabel, step, index, `${where}[${inputIndex}] lockingBytecode differs`);
    }
  });
};

const compareOptionalTokenShape = (
  left: { capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array } | undefined,
  right: { capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array } | undefined,
  runLabel: string,
  step: Step,
  index: number,
  where: string,
): void => {
  if ((left === undefined) !== (right === undefined)) failStep(runLabel, step, index, `${where} presence differs`);
  if (left !== undefined && right !== undefined && left.capability !== right.capability) {
    failStep(runLabel, step, index, `${where}.capability differs`);
  }
};

const assertSameStepProgram = (primary: Step, candidate: Step, index: number, label: string): void => {
  if (!bytesEqual(primary.lockingBytecode, candidate.lockingBytecode)) {
    failStep(label, candidate, index, 'lockingBytecode differs from the primary run');
  }
  const primaryKind = contextKind(primary, label, index);
  const candidateKind = contextKind(candidate, label, index);
  if (primaryKind !== candidateKind) failStep(label, candidate, index, `context kind differs from primary (${primaryKind} vs ${candidateKind})`);
  if (primaryKind === 'covenant') {
    const left = primary.covenant!;
    const right = candidate.covenant!;
    if (!bytesEqual(left.category, right.category)) failStep(label, candidate, index, 'covenant.category differs');
    if (left.capability !== right.capability) failStep(label, candidate, index, 'covenant.capability differs');
    if (left.inputCapability !== right.inputCapability) failStep(label, candidate, index, 'covenant.inputCapability differs');
    if (left.secondOutputBaton !== right.secondOutputBaton) failStep(label, candidate, index, 'covenant.secondOutputBaton differs');
    if (!bytesEqual(left.outLockingBytecode, right.outLockingBytecode)) failStep(label, candidate, index, 'covenant successor locking differs');
  }
  if (primaryKind === 'intraTx') {
    const left = primary.intraTx!;
    const right = candidate.intraTx!;
    if (left.index !== right.index) failStep(label, candidate, index, 'intraTx.index differs');
    compareInputLockings(left.inputs, right.inputs, label, candidate, index, 'intraTx.inputs');
  }
  if (primaryKind === 'grouped') {
    const left = primary.grouped!;
    const right = candidate.grouped!;
    if (left.group !== right.group || left.index !== right.index) failStep(label, candidate, index, 'grouped topology differs');
    if (!bytesEqual(left.category, right.category)) failStep(label, candidate, index, 'grouped.category differs');
    compareInputLockings(left.inputs, right.inputs, label, candidate, index, 'grouped.inputs');
    compareOptionalTokenShape(left.inToken, right.inToken, label, candidate, index, 'grouped.inToken');
    compareOptionalTokenShape(left.outToken, right.outToken, label, candidate, index, 'grouped.outToken');
    const leftTokens = left.inputTokens;
    const rightTokens = right.inputTokens;
    if ((leftTokens === undefined) !== (rightTokens === undefined)) failStep(label, candidate, index, 'grouped.inputTokens presence differs');
    if (leftTokens !== undefined && rightTokens !== undefined) {
      if (leftTokens.length !== rightTokens.length) failStep(label, candidate, index, 'grouped.inputTokens topology differs');
      leftTokens.forEach((token, tokenIndex) => compareOptionalTokenShape(token, rightTokens[tokenIndex], label, candidate, index, `grouped.inputTokens[${tokenIndex}]`));
    }
    if ((left.outLockingBytecode === undefined) !== (right.outLockingBytecode === undefined)) {
      failStep(label, candidate, index, 'grouped successor locking presence differs');
    }
    if (left.outLockingBytecode !== undefined && right.outLockingBytecode !== undefined && !bytesEqual(left.outLockingBytecode, right.outLockingBytecode)) {
      failStep(label, candidate, index, 'grouped successor locking differs');
    }
  }
};

/** Confirm only the deployed program/topology is shared; witness bytes are intentionally ignored. */
export const assertSameProgramRun = (primary: Step[], run: Step[], label: string): void => {
  assertRunShape(primary, 'primary run');
  assertRunShape(run, label);
  if (run.length !== primary.length) failRun(label, `step count ${run.length} differs from primary count ${primary.length}`);
  run.forEach((step, index) => assertSameStepProgram(primary[index]!, step, index, label));
};

type DecodedProofComponent = { locator: ProofInput; value: string };

const locatorError = (runLabel: string, locatorIndex: number, reason: string): never => {
  throw new Error(`${runLabel}: proofInputs[${locatorIndex}] ${reason}`);
};

const validInteger = (value: unknown): value is number => typeof value === 'number' && Number.isInteger(value);

const proofComponents = (run: Step[], locators: ProofInput[], runLabel: string): DecodedProofComponent[] => {
  return locators.map((locator, locatorIndex) => {
    if (!locator || typeof locator !== 'object') locatorError(runLabel, locatorIndex, 'is not an object');
    if (!validInteger(locator.input) || locator.input < 0 || locator.input >= run.length) locatorError(runLabel, locatorIndex, `has invalid input index ${String(locator.input)}`);
    if (!validInteger(locator.push) || locator.push < 0) locatorError(runLabel, locatorIndex, `has invalid push index ${String(locator.push)}`);
    const encoding = locator.encoding ?? 'vm-number';
    if (encoding !== 'vm-number' && encoding !== 'bytes') locatorError(runLabel, locatorIndex, `has unsupported encoding ${String(encoding)}`);
    if (encoding === 'vm-number' && (locator.offset !== undefined || locator.length !== undefined)) {
      locatorError(runLabel, locatorIndex, 'vm-number locators cannot specify offset or length');
    }
    const step = run[locator.input]!;
    let instructions: ReturnType<typeof decodeAuthenticationInstructions> | undefined;
    try {
      instructions = decodeAuthenticationInstructions(step.unlockingBytecode);
    } catch (error) {
      locatorError(runLabel, locatorIndex, `cannot decode ${stepName(step, locator.input)}: ${String(error)}`);
    }
    const decodedInstructions = instructions ?? locatorError(runLabel, locatorIndex, 'could not decode unlocking bytecode');
    const instruction = decodedInstructions[locator.push];
    if (instruction === undefined) locatorError(runLabel, locatorIndex, `push index ${locator.push} is out of bounds at ${stepName(step, locator.input)}`);
    const data = 'data' in instruction ? instruction.data : undefined;
    if (encoding === 'vm-number') {
      let value: bigint | undefined;
      if (instruction.opcode === 0) value = 0n;
      else if (instruction.opcode === 0x4f) value = -1n;
      else if (instruction.opcode >= 0x51 && instruction.opcode <= 0x60) value = BigInt(instruction.opcode - 0x50);
      else if (data !== undefined) {
        const decoded = vmNumberToBigInt(data, { requireMinimalEncoding: false });
        if (typeof decoded === 'bigint') value = decoded;
      }
      const numericValue = value ?? locatorError(runLabel, locatorIndex, `push ${locator.push} at ${stepName(step, locator.input)} is not a VM-number push`);
      return { locator, value: `n:${numericValue.toString(10)}` };
    }
    const length = validInteger(locator.length) && locator.length > 0
      ? locator.length
      : locatorError(runLabel, locatorIndex, 'bytes encoding requires a positive length');
    const offset = locator.offset ?? 0;
    if (!validInteger(offset) || offset < 0) locatorError(runLabel, locatorIndex, 'bytes encoding requires a non-negative offset');
    const pushData = data ?? locatorError(runLabel, locatorIndex, `push ${locator.push} at ${stepName(step, locator.input)} is not a data push`);
    if (offset + length > pushData.length) locatorError(runLabel, locatorIndex, `byte range [${offset}, ${offset + length}) is out of bounds for push ${locator.push}`);
    return { locator, value: `b:${bytesHex(pushData.subarray(offset, offset + length))}` };
  });
};

const proofFingerprint = (run: Step[], locators: ProofInput[], runLabel: string): string =>
  JSON.stringify(proofComponents(run, locators, runLabel).map((component) => [
    component.locator.input,
    component.locator.push,
    component.locator.encoding ?? 'vm-number',
    component.locator.offset ?? 0,
    component.locator.length ?? null,
    component.value,
  ]));

export type HonestRunsResult = {
  proofIdentity: BenchmarkResult['proofIdentity'];
  distinctExtraProofs: Step[][];
};

/** Enforce scenario contracts before any VM run or benchmark measurement. */
export const assertHonestRuns = (
  impl: Implementation,
  scenario: Pick<Scenario, 'valid' | 'extraValidProofs' | 'worstCaseProof'>,
): HonestRunsResult => {
  assertRunShape(scenario.valid, `${impl.id}: valid`);
  const extras = scenario.extraValidProofs ?? [];
  if (!Array.isArray(extras)) failRun(`${impl.id}: scenario`, 'extraValidProofs must be an array');
  extras.forEach((run, index) => {
    assertSameProgramRun(scenario.valid, run, `${impl.id}: extra proof #${index + 1}`);
  });
  if (scenario.worstCaseProof !== undefined) {
    assertSameProgramRun(scenario.valid, scenario.worstCaseProof, `${impl.id}: worst-case proof`);
  }

  const locators = impl.proofInputs;
  if (locators !== undefined && !Array.isArray(locators)) failRun(`${impl.id}: proofInputs`, 'must be an array');
  if (locators === undefined || locators.length === 0) {
    return {
      proofIdentity: {
        declared: false,
        distinct: false,
        reason: 'proofInputs locators are missing; no extra proof can be qualified',
      },
      distinctExtraProofs: [],
    };
  }

  const fingerprints = new Map<string, string>();
  const primaryFingerprint = proofFingerprint(scenario.valid, locators, `${impl.id}: valid`);
  fingerprints.set(primaryFingerprint, 'valid');
  const distinctExtraProofs: Step[][] = [];
  extras.forEach((run, index) => {
    const label = `${impl.id}: extra proof #${index + 1}`;
    const fingerprint = proofFingerprint(run, locators, label);
    const previous = fingerprints.get(fingerprint);
    if (previous !== undefined) failRun(label, `proof fingerprint duplicates ${previous}`);
    fingerprints.set(fingerprint, `extra proof #${index + 1}`);
    distinctExtraProofs.push(run);
  });
  if (scenario.worstCaseProof !== undefined) {
    // Validate its declared components, but do not use this density fixture as an honest-proof identity.
    proofFingerprint(scenario.worstCaseProof, locators, `${impl.id}: worst-case proof`);
  }
  return {
    proofIdentity: {
      declared: true,
      distinct: distinctExtraProofs.length > 0,
      ...(distinctExtraProofs.length === 0 ? { reason: 'no distinct extra valid proof run supplied' } : {}),
    },
    distinctExtraProofs,
  };
};
