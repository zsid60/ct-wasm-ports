const crypto  = require('crypto');
const fs = require('fs');
const {promisify, rdtscp} = require('util');
const readFileAsync = promisify(fs.readFile);
const int64 = require('node-int64');

const EC = require('elliptic').ec;
const EdDSA = require('elliptic').eddsa;

const BN = require('bn.js');

function getRand(max) {
  return Math.floor(Math.random() * Math.floor(max));
}

function performSign(key, message, rounds) {
  for (let j = 0; j < rounds; j++) {
    key.sign(message);
  }
}

function perform1Sign(key, message) {
  return key.sign(message);
}

async function benchmarkDriver() {

  const num_classes = 50;
  const number_measurements = 20000 * num_classes;
  const warmup  = 1000;
  const rounds = 1;

  let msgs = Array();
  for (let i = 0; i < num_classes; i++) {
    msgs[i] = "Hello this is test message " + i;
  }
  
  const hs = msgs.map( m => crypto.createHash('sha256').update(m).digest());
  
  
  const curves = ['ed25519', 'secp256k1', 'p224', 'p521'];
  const curve_num = 1;

  let ec;
  if (curve_num == 0) {
    ec = new EdDSA(curves[curve_num]);
  } else {
    ec = new EC(curves[curve_num]);
  }

  // Arbitrary key
  const n = new BN('be95faed2ce5554ea4a7e51342635c75bad4e50fd81281d83a8276ed483f4bc8', 16);
  const key = ec.keyFromPrivate(n);
  
  let classes = new Array();
  for (let i = 0; i < number_measurements; i++) {
    classes.push(getRand(num_classes));
  }

  const hs_for_meas = Array();
  for (let i = 0; i < number_measurements; i++) {
    hs_for_meas.push(hs[classes[i]]);
  }
  

  let sigs = new Array(num_classes);
  let nonces = new Array(num_classes);

  for (let i = 0; i < hs.length; i++) {
    sigs[i] = perform1Sign(key, hs[i], 1);

  }
  
  for (let j = 0; j < sigs.length; j++) {
    let sig = sigs[j];
    let h = ec._truncateToN(new BN(hs[j], 16));

    /*
    console.log("j = " + j);
    console.log("sig = " + sig);
    console.log("h = " + h);
    let x1 = sig.s.invm(ec.n);
    console.log("x1: " + x1)
    let x2 = key.getPrivate();
    console.log("x2: " + x2)
    let x3 = sig.r.mul(x2);
    console.log("x3: " + x3)
    let x4 = x3.iadd(h);
    console.log("x4: " + x4)
    let x5 = x1.mul(x4);
    console.log("x5: " + x5)
    nonces[j] = x5;
    */

    nonces[j] = sig.s.invm(ec.n).mul(sig.r.mul(key.getPrivate()).iadd(h)).umod(ec.n);
  }

  console.log("Begin warmup");

  // run node with --allow-natives-syntax
  %OptimizeFunctionOnNextCall(perform1Sign);
 
  for (let i = 0; i < warmup; i++) {
    perform1Sign(key, hs[0], 1);
  }
  
  console.log("Finished warmup");
  
  let measurements = hs.map(c => new Array());

  for (let i = 0; i < number_measurements; i++) {
    let hash_of_m = hs_for_meas[i]
    let start = rdtscp();
    let sig = perform1Sign(key, hash_of_m, rounds);
    let end = rdtscp();

    let diff = new int64(end[1], end[0]) - new int64(start[1], start[0]);
    measurements[classes[i]].push(diff)
    
    if (i % (number_measurements / 20) == 0) {
      console.log("iter " + i + " done");
    }
  }

  fs.writeFile('classes.log',
    classes.join('\n') + '\n',
    err => { if (err) throw err; });

  for (let i = 0; i < num_classes; i++) {
    fs.writeFile('test_output/times' + i + '.log',
    measurements[i].map(m => m.toString()).join('\n') + '\n',
    err => { if (err) throw err; });
  }  

  fs.writeFile('test_output/sigs.log',
    sigs.map(sig => "r: " + sig.r.toString(16,32) + "\ts: " + sig.s.toString(16,32) + "\t recovery: " + sig.recoveryParam).join('\n') + '\n',
    err => { if (err) throw err; });
  
  fs.writeFile('test_output/nonces.log', 
    nonces.map(n => n.toString(16,32) + '  (' + n.bitLength() + ' bits)').join('\n') + '\n',
    err => { if (err) throw err; });
    

}

benchmarkDriver().catch(err => console.log(err));
