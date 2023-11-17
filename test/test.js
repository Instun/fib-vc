const keyJson = require("./data/keys/key-0-ed25519.json");
const credentialWithoutProof = require("./data/credentials/credential-3.json");
var ssl = require('ssl');
var crypto = require('crypto');
var vc = require("..");
var dkey = require("fib-did-key");

vc.contexts["did:example:123"] = keyJson;

console.log("============= credentialWithoutProof", credentialWithoutProof);

var c = vc.credential.issue({
    credential: credentialWithoutProof,
    date: credentialWithoutProof.issuanceDate,
    id: keyJson.id,
    key: keyJson.privateKeyJwk
});

console.log("============= credential", c);
// c.name = 'lion';
// c.credentialSubject.id = 'did:example:123';

var r = vc.credential.verify({
    credential: c
});

console.log(r);
