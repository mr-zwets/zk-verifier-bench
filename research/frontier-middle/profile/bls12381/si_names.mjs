import {buildRedeem} from './src/sound-si-gls/script.mjs';
import { readFileSync } from 'node:fs';
const {redeem, info} = buildRedeem();
const v = JSON.parse(readFileSync('/home/mrzwets/BCH-projects/verifier.cash/zk-verifier-bench/src/bch/groth16-bls12381-sound-si-gls-single-vectors.json','utf8'));
const hex = Buffer.from(redeem).toString('hex');
console.log('redeem', redeem.length, 'in vector unlocking:', v.steps[0].unlocking.includes(hex));
console.log(JSON.stringify(info).slice(0,3000));
