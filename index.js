const process = require('process');
const minimist = require('minimist');
const encrypt = require('./lib/encrypt');

function usage() {
    console.log(`Usage:
    node index.js --plaintext=<PLAINTEXT> --password=<PASSWORD>`);
}

const { plaintext, password } = minimist(process.argv);

if (!plaintext) {
    usage();
    return 1;
}

if (!password) {
    usage();
    return 2;
}

const encrypted = encrypt(plaintext, password);
console.log(encrypted);
