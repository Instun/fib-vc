var vc = require("..");

const keyJson = require("./data/keys/key-0-ed25519.json");
const credentialWithoutProof = require("./data/credentials/credential-3.json");

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
    credential: c,
    key: keyJson
});

console.log(r);
