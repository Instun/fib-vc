var ssl = require('ssl');
var vc = require("..");
var dkey = require("fib-did-key");

ssl.loadRootCerts();

const credential = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: "http://example.edu/credentials/3732",
    type: ["VerifiableCredential"],
    issuer: {
        id: 'did:key:z6MkokrsVo8DbGDsnMAjnoHhJotMbDZiHfvxM4j65d8prXUr#z6MkokrsVo8DbGDsnMAjnoHhJotMbDZiHfvxM4j65d8prXUr',
    },
    issuanceDate: "2010-01-01T19:23:24Z",
    credentialSubject: {
        id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
    },
};

var c = vc.credential.issue({
    credential,
    key: {
        kty: "OKP",
        crv: "Ed25519",
        x: "ijtvFnowiumYMcYVbaz6p64Oz6bXwe2V_9IlCgDR_38",
        d: "ZrHpIW1JBb-sK2-wzKV0mQjbxpnxjUCu151QZ9_F_Vs",
    }
});

var r = vc.credential.verify({
    credential: c
});

console.log(c);
console.log(r);
