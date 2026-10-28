// Independent symbolic operand/accumulator transport, not a VM or fixture test.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {decodeAuthenticationInstructions, OpcodesBCH as O, vmNumberToBigInt} from '@bitauth/libauth';
const read = path => readFileSync(new URL(path, import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const bytes = Buffer.from(read('./compiled-locking.hex').toString().trim(), 'hex');
assert.equal(sha(bytes), 'c34b223e101f14b5a53bb9d6ab9fed3fd6a7174501a9a4fb1ddc36897f466ca1');
const outer = decodeAuthenticationInstructions(bytes), body = decodeAuthenticationInstructions(outer[0].data);
const transfer = JSON.parse(read('./callee-transfer.json'));
for (const [oldId, newId] of [[8, 5], [10, 7], [1, 1], [2, 2], [3, 3]]) {
  assert(transfer.matches.find(row => row.oldId === oldId).newMatches.some(row => row.id === newId));
}
const r = '52435875175126190479447740508185965837690552500527637822603658699938581184513';
const p = '4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787';
const expression = (name, ...args) => `${name}(${args.join(',')})`;
function number(item) {
  if (item.opcode === O.OP_0) return '0';
  if (item.opcode >= O.OP_1 && item.opcode <= O.OP_16) return String(item.opcode - 80);
  if (item.data !== undefined) return vmNumberToBigInt(item.data, {requireMinimalEncoding: false}).toString();
}
function run(start, end, initial, choices) {
  const stack = [...initial], alt = [], calls = [], guards = [], branches = [], until = [];
  const pop = () => { assert(stack.length > 1, 'Caller prefix cannot be consumed'); return stack.pop(); };
  const binary = name => { const b = pop(), a = pop(); stack.push(expression(name, a, b)); };
  const matchIf = at => {
    let depth = 0, otherwise;
    for (let i = at + 1; i < body.length; i++) {
      if (body[i].opcode === O.OP_IF) depth++;
      if (body[i].opcode === O.OP_ELSE && depth === 0) otherwise = i;
      if (body[i].opcode === O.OP_ENDIF) {
        if (depth === 0) return {otherwise, end: i};
        depth--;
      }
    }
    throw new Error('Unclosed IF');
  };
  for (let i = start; i <= end; i++) {
    const op = body[i].opcode, literal = number(body[i]);
    if (literal !== undefined) { stack.push(literal); continue; }
    if (op === O.OP_IF) {
      const predicate = pop(), take = choices[i]; assert.equal(typeof take, 'boolean', `Branch ${i}`);
      branches.push({instruction: i, predicate, take});
      if (!take) { const block = matchIf(i); i = block.otherwise ?? block.end; }
    } else if (op === O.OP_ELSE) i = matchIf(i).end;
    else if (op === O.OP_ENDIF) { /* no stack effect */ }
    else if (op === O.OP_DUP) stack.push(stack.at(-1));
    else if (op === O.OP_2DUP) stack.push(...stack.slice(-2));
    else if (op === O.OP_OVER) stack.push(stack.at(-2));
    else if (op === O.OP_2OVER) stack.push(...stack.slice(-4, -2));
    else if (op === O.OP_DROP) pop();
    else if (op === O.OP_2DROP) { pop(); pop(); }
    else if (op === O.OP_NIP) { const top = pop(); pop(); stack.push(top); }
    else if (op === O.OP_SWAP) { const b = pop(), a = pop(); stack.push(b, a); }
    else if (op === O.OP_ROT) { const c = pop(), b = pop(), a = pop(); stack.push(b, c, a); }
    else if (op === O.OP_2ROT) { assert(stack.length > 6); stack.push(...stack.splice(-6, 2)); }
    else if (op === O.OP_2SWAP) { const values = stack.splice(-4); stack.push(...values.slice(2), ...values.slice(0, 2)); }
    else if (op === O.OP_PICK || op === O.OP_ROLL) {
      const depth = Number(pop()); assert(Number.isInteger(depth) && depth >= 0 && depth < stack.length - 1);
      const at = stack.length - 1 - depth;
      stack.push(op === O.OP_PICK ? stack[at] : stack.splice(at, 1)[0]);
    } else if (op === O.OP_TOALTSTACK) alt.push(pop());
    else if (op === O.OP_FROMALTSTACK) { assert(alt.length); stack.push(alt.pop()); }
    else if (op === O.OP_WITHIN) { const upper = pop(), lower = pop(), x = pop(); stack.push(expression('within', x, lower, upper)); }
    else if (op === O.OP_VERIFY) guards.push(pop());
    else if (op === O.OP_NUMEQUALVERIFY) { const b = pop(), a = pop(); guards.push(expression('eq', a, b)); }
    else if (op === O.OP_INVOKE) {
      const id = Number(pop()), inputs = {1: 1, 2: 2, 3: 2, 5: 3, 7: 5}[id]; assert(inputs);
      const args = Array.from({length: inputs}, pop); let outputs;
      if (id <= 3) outputs = [expression({1: 'sqr', 2: 'mul', 3: 'add'}[id], ...args)];
      else outputs = ['x', 'y', 'z'].map(axis => expression(id === 5 ? `double.${axis}` : `add.${axis}`, ...args));
      calls.push({instruction: i, id, args, outputs}); stack.push(...outputs);
    } else if (op === O.OP_1ADD) stack.push(expression('add', pop(), '1'));
    else if (op === O.OP_NOT) stack.push(expression('not', pop()));
    else if (op === O.OP_UNTIL) until.push(pop());
    else {
      const name = new Map([[O.OP_ADD,'add'],[O.OP_SUB,'sub'],[O.OP_MOD,'mod'],[O.OP_RSHIFTNUM,'shr'],
        [O.OP_LESSTHAN,'lt'],[O.OP_NUMNOTEQUAL,'neq'],[O.OP_NUMEQUAL,'eq']]).get(op);
      assert(name, `Unsupported opcode ${op} at ${i}`); binary(name);
    }
  }
  assert.equal(stack[0], 'caller'); assert.equal(alt.length, 0);
  return {stack, calls, guards, branches, until};
}
const prefix = run(0, 29, ['caller', 'y', 'x'], {});
assert.deepEqual(prefix.guards, [expression('within','x','0',p), expression('within','y','0',p),
  expression('eq',expression('sqr','y'),expression('add',expression('mul',expression('sqr','x'),'x'),'4'))]);
assert.deepEqual(prefix.stack, ['caller','y','x','0','1','0',r,'0']);
const paths = [];
for (const finite of [false, true]) for (const bit of [false, true]) {
  const R = ['Rx','Ry',finite ? 'Rz' : '0'];
  const step = run(31,180,['caller','y','x',...R,r,'k'],{36:true,44:finite,110:bit});
  assert.deepEqual(step.branches.map(item => item.predicate), [expression('lt','k','255'),
    expression('neq',R[2],'0'), expression('eq',expression('mod',expression('shr',r,expression('sub','254','k')),'2'),'1')]);
  const D = finite ? ['x','y','z'].map(axis => expression(`double.${axis}`,...R)) : R;
  const next = bit ? ['x','y','z'].map(axis => expression(`add.${axis}`,...D,'x','y')) : D;
  if (finite) assert.deepEqual(step.calls.find(item => item.id === 5).args,R);
  if (bit) assert.deepEqual(step.calls.find(item => item.id === 7).args,[...D,'x','y']);
  assert.deepEqual(step.stack,['caller','y','x',...next,r,expression('add','k','1')]);
  assert.deepEqual(step.until,[expression('not',expression('lt','k','255'))]);
  paths.push({finite,bit,...step});
}
const exit = run(31,187,['caller','y','x','Rx','Ry','Rz',r,'255'],{36:false});
assert.deepEqual(exit.stack,['caller']); assert.deepEqual(exit.guards,[expression('eq','Rz','0')]);
const report = {schema:'bls-strict-g1-symbolic-loop-operands/v1',status:'PASS_ACTUAL_GUARDS_CALL_OPERANDS_ACCUMULATOR_BACKEDGE_AND_EXIT',
  artifactSha256:sha(bytes),checkerSha256:sha(read('./check-g1-subgroup.mjs')),
  prefix,paths,exit,scalar:r,
  conclusion:'The actual canonical/curve guards and all four loop paths preserve the original finite x,y and caller prefix; callee operands/returns implement R -> 2R+bit*P, k -> k+1, for exactly255bits of r. The actual final check is Z([r]P)=0. Transferred complete Jacobian formulas give strict order-r membership for finite points.',
  activity:{vmRuns:0,newProofCases:0,negativeCases:0,byteOptimization:false}};
writeFileSync(new URL('g1-loop-operands.json',import.meta.url),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({status:report.status,paths:paths.length}));
