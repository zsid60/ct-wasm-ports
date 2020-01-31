const assert = require('assert');
const crypto  = require('crypto');
const fs = require('fs');
const {promisify, rdtscp} = require('util');
const readFileAsync = promisify(fs.readFile);
const int64 = require('node-int64');
const EC = require('elliptic').ec 

function getRand(max) {
  return Math.floor(Math.random() * Math.floor(max));
}

function performSign(key, message, rounds) {
  for (let j = 0; j < rounds; j++) {
    key.sign(message)
  }
}

async function benchmarkDriver() {
  const number_measurements = 1e4;
  const rounds = 10;
  const warmup  = 1000;

  const msg_str = "Hello this is a test message"
  const message = crypto.createHash('sha256').update(msg_str).digest();  

  const ec = new EC('secp256k1');
  //const ec = new EC('p224');
  //const ec = new EC('p521');

  let classes = new Array();
  for (let i = 0; i < number_measurements; i++) {
    classes.push(getRand(2));
  }


  let keys = new Array();
  for (let i = 0; i < number_measurements; i++) {
    keys.push(ec.genKeyPair());
    if (classes[i] == 0) {
      const key_size = keys[i]['priv']['length'];
      for (let j = 0; j < key_size; j++) {
        keys[i]['priv']['words'][j] = 0;
      }
    } 
  }
  
  for (let i = 0; i < warmup; i++) {
    performSign(keys[0], message, 1);
  }
 
  // run node with --allow-natives-syntax
  %OptimizeFunctionOnNextCall(performSign);
 

  let measurements = new Array();
  for (let i = 0; i < number_measurements; i++) {
    let k = keys[i]
    measurements.push(rdtscp());

    for (let j = 0; j < rounds; j++) {
      performSign(k, message, rounds)  
    }
  }
  measurements.push(rdtscp());

  fs.writeFile('params.log',
    [number_measurements].join('\n') + '\n',
    err => { if (err) throw err; });

  fs.writeFile('classes.log',
    classes.join('\n') + '\n',
    err => { if (err) throw err; });

  fs.writeFile('output.log',
    measurements.map(m => new int64(m[1], m[0]).toOctetString()).join('\n') + '\n',
    err => { if (err) throw err; });
}

benchmarkDriver().catch(err => console.log(err));
