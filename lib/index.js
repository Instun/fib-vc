var crypto = require('crypto');
var hash = require("hash");
var jsonld = require("fib-jsonld");
var dkey = require("fib-did-key");
var docs = require("./docs");

function documentLoader(url) {
    var d = docs[url];
    if (d)
        return {
            "documentUrl": url,
            "document": d
        };

    return jsonld.documentLoader(url);
}

function issue({ credential, id, key, date, proofPurpose }) {
    credential = {
        ...credential
    };

    if (credential.proof)
        delete credential.proof;

    if (!(key instanceof crypto.PKey))
        key = crypto.PKey.from(key);

    if (!id) {
        var fingerprint = dkey.fingerprint(key);
        id = `did:key:${fingerprint}#${fingerprint}`;
    }

    var proof = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/suites/jws-2020/v1'
        ],
        type: 'JsonWebSignature2020',
        created: date || new Date().toISOString(),
        verificationMethod: id,
        proofPurpose: proofPurpose || 'assertionMethod'
    };

    var data = Buffer.concat([
        hash.sha256(jsonld.canonize(proof, {
            documentLoader
        })).digest(),
        hash.sha256(jsonld.canonize(credential, {
            documentLoader
        })).digest()
    ]);

    proof.jws = dkey.sign(data, key);
    delete proof['@context'];

    credential.proof = proof;

    return credential;
}

function verify({ credential, key }) {
    try {
        credential = {
            ...credential
        };
        var proof = {
            '@context': [
                'https://www.w3.org/2018/credentials/v1',
                'https://w3id.org/security/suites/jws-2020/v1'
            ],
            ...credential.proof
        };
        var jws = proof.jws;

        delete proof.jws;
        delete credential.proof;

        var data = Buffer.concat([
            hash.sha256(jsonld.canonize(proof, {
                documentLoader
            })).digest(),
            hash.sha256(jsonld.canonize(credential, {
                documentLoader
            })).digest()
        ]);

        if (!key) {
            var id = proof.verificationMethod;
            dkey.resolve(id).keys.forEach(k => {
                if (k.id == id)
                    key = k.publicKeyJwk;
            });
        }

        if (!key instanceof crypto.PKey)
            key = crypto.PKey.from(key);

        return {
            verified: dkey.verify(data, jws, key)
        }
    } catch (e) {
        return {
            verified: false,
            error: e
        };
    }
}

module.exports = {
    credential: {
        issue,
        verify
    },
    presentation: {}
};
