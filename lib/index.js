var crypto = require('crypto');
var hash = require("hash");
var util = require("util");
var jsonld = require("fib-jsonld");
var dkey = require("fib-did-key");
var contexts = require("./contexts");

const cache = new util.LruCache(1000);
const sync_loader = util.sync(async (url, opts) => await jsonld._documentLoader(url, opts), true);
const jsonld_documentLoader = jsonld._documentLoader;

jsonld._documentLoader = async function (url, opts) {
    var uerls = url.split('#');
    var d = contexts[uerls[0]] || cache.get(uerls[0]);
    if (d)
        return {
            "documentUrl": uerls[0],
            "document": d
        };

    var doc = await jsonld_documentLoader(uerls[0], opts);
    cache.set(uerls[0], doc.document);

    return doc;
}

function credential_issue({ credential, id, key, date, proofPurpose }) {
    credential = {
        ...credential
    };

    if (credential.proof)
        delete credential.proof;

    if (!id) {
        var fingerprint = dkey.fingerprint(key);
        id = `did:key:${fingerprint}#${fingerprint}`;
    }

    var proof = {
        '@context': credential['@context'],
        type: 'JsonWebSignature2020',
        created: date || new Date().toISOString(),
        verificationMethod: id,
        proofPurpose: proofPurpose || 'assertionMethod'
    };

    var data = Buffer.concat([
        hash.sha256(jsonld.canonize(proof, {
            documentLoader: jsonld._documentLoader
        })).digest(),
        hash.sha256(jsonld.canonize(credential, {
            documentLoader: jsonld._documentLoader
        })).digest()
    ]);

    proof.jws = dkey.sign(data, key);
    delete proof['@context'];

    credential.proof = proof;

    return credential;
}

function credential_verify({ credential, key }) {
    try {
        credential = {
            ...credential
        };
        var proof = {
            '@context': credential['@context'],
            ...credential.proof
        };
        var jws = proof.jws;

        delete proof.jws;
        delete credential.proof;

        var data = Buffer.concat([
            hash.sha256(jsonld.canonize(proof, {
                documentLoader: jsonld._documentLoader
            })).digest(),
            hash.sha256(jsonld.canonize(credential, {
                documentLoader: jsonld._documentLoader
            })).digest()
        ]);

        var id = proof.verificationMethod;
        if (!key) {
            if (id.substr(0, 8) === 'did:key:')
                key = dkey.resolve(id);
            else
                key = sync_loader(id).document;
        }

        if (!(key instanceof crypto.PKey)) {
            if (key.keys)
                for (var i = 0; i < key.keys.length; i++) {
                    var k = key.keys[i];
                    if (k.id == id) {
                        key = k.publicKeyJwk;
                        break;
                    }
                }
            else if (key.id == id)
                key = key.publicKeyJwk;
            else
                throw new Error('Not found key');
        }

        return {
            verified: dkey.verify(data, jws, key),
            key: key
        }
    } catch (e) {
        return {
            verified: false,
            error: e
        };
    }
}

module.exports = {
    contexts: contexts,
    credential: {
        issue: credential_issue,
        verify: credential_verify
    },
    presentation: {}
};
