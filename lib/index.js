var crypto = require('crypto');
var util = require("util");
var jsonld = require("fib-jsonld");
var dkey = require("fib-did-key");
var contexts = require("./contexts");

const cache = new util.LruCache(1000);
const sync_loader = util.sync(async (url, opts) => await jsonld._documentLoader(url, opts), true);
const jsonld_documentLoader = jsonld._documentLoader;

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

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

function check_type(ld, type) {
    if (type) {
        if (Array.isArray(ld.type)) {
            if (ld.type.indexOf(type) < 0)
                throw new Error(`Invalid type: ${ld.type}`);
        } else if (ld.type !== type)
            throw new Error(`Invalid type: ${ld.type}`);
    }
}

function jsigs_issue({ ld, type, id, key, date, proofPurpose, challenge }) {
    check_type(ld, type);

    ld = {
        ...ld
    };

    if (ld.proof)
        delete ld.proof;

    if (!id) {
        var fingerprint = dkey.fingerprint(key);
        id = `did:key:${fingerprint}#${fingerprint}`;
    }

    var proof = {
        '@context': ld['@context'],
        type: 'JsonWebSignature2020',
        created: date || new Date().toISOString(),
        verificationMethod: id,
        proofPurpose: proofPurpose || 'assertionMethod'
    };

    if (challenge) {
        if (typeof challenge !== "string")
            throw new TypeError('"challenge" must be a string.');
        proof.challenge = challenge;
    }

    var data = Buffer.concat([
        sha256(jsonld.canonize(proof, {
            documentLoader: jsonld._documentLoader
        })),
        sha256(jsonld.canonize(ld, {
            documentLoader: jsonld._documentLoader
        }))
    ]);

    proof.jws = dkey.sign(data, key);
    delete proof['@context'];

    ld.proof = proof;

    return ld;
}

function jsigs_verify({ ld, type, key }) {
    try {
        check_type(ld, type);
        if (ld.proof.type !== 'JsonWebSignature2020')
            throw new Error('Invalid proof type');

        ld = {
            ...ld
        };

        var proof = {
            '@context': ld['@context'],
            ...ld.proof
        };
        var jws = proof.jws;

        delete proof.jws;
        delete ld.proof;

        var data = Buffer.concat([
            sha256(jsonld.canonize(proof, {
                documentLoader: jsonld._documentLoader
            })),
            sha256(jsonld.canonize(ld, {
                documentLoader: jsonld._documentLoader
            }))
        ]);

        var id = proof.verificationMethod;
        if (!key) {
            if (id.substr(0, 8) === 'did:key:')
                key = dkey.resolve(id);
            else
                key = sync_loader(id).document;
        }

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

        return {
            verified: dkey.verify(data, jws, key),
            id,
            key: key
        }
    } catch (e) {
        return {
            verified: false,
            error: e
        };
    }
}

function credential_issue({ credential, id, key, date, proofPurpose }) {
    return jsigs_issue({ ld: credential, type: "VerifiableCredential", id, key, date, proofPurpose });
}

function credential_verify({ credential, key }) {
    return jsigs_verify({ ld: credential, type: "VerifiableCredential", key });
}

function presentation_issue({ presentation, id, key, date, proofPurpose, challenge }) {
    if (typeof challenge !== "string")
        throw new TypeError('"challenge" must be a string.');
    return jsigs_issue({ ld: presentation, type: "VerifiablePresentation", id, key, date, proofPurpose, challenge });
}

function presentation_verify({ presentation, key }) {
    if (typeof presentation.proof.challenge !== "string")
        throw new TypeError('"challenge" must be a string.');
    return jsigs_verify({ ld: presentation, type: "VerifiablePresentation", key });
}

module.exports = {
    contexts: contexts,
    jsigs: {
        issue: jsigs_issue,
        verify: jsigs_verify
    },
    credential: {
        issue: credential_issue,
        verify: credential_verify
    },
    presentation: {
        issue: presentation_issue,
        verify: presentation_verify
    }
};
