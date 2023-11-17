const test = require('test');
test.setup();

const fs = require('fs');
const path = require('path');
const vc = require("../lib");

const keys = fs.readdir(path.join(__dirname, "./data/keys")).map(key => path.basename(key, ".json"));
const creds = fs.readdir(path.join(__dirname, "./data/credentials")).map(cred => path.basename(cred, ".json"));
const impls = fs.readdir(path.join(__dirname, "./data/implementations"));

describe("vc", () => {
    describe("issue/verify", () => {
        creds.forEach(cred => {
            const credJson = require(`./data/credentials/${cred}.json`);
            keys.forEach(key => {
                if (key != "key-4-rsa2048") {
                    const keyJson = require(`./data/keys/${key}.json`);
                    it(`${cred}--${key}`, () => {
                        var vcJson = vc.credential.issue({
                            credential: credJson,
                            date: credJson.issuanceDate,
                            id: keyJson.id,
                            key: keyJson.privateKeyJwk
                        });

                        var r = vc.credential.verify({
                            credential: vcJson,
                            key: keyJson
                        });

                        assert.isUndefined(r.error);
                    });
                }
            });
        });
    });

    describe("implementations", () => {
        impls.forEach(impl => {
            describe(`${impl}`, () => {
                creds.forEach(cred => {
                    const credJson = require(`./data/credentials/${cred}.json`);
                    keys.forEach(key => {
                        if (key != "key-4-rsa2048") {
                            const keyJson = require(`./data/keys/${key}.json`);
                            if (fs.exists(path.join(__dirname, `./data/implementations/${impl}/${cred}--${key}.vc.json`)))
                                it(`${cred}--${key}`, () => {
                                    const vcJson = require(`./data/implementations/${impl}/${cred}--${key}.vc.json`);
                                    var r = vc.credential.verify({
                                        credential: vcJson,
                                        key: keyJson
                                    });

                                    assert.isUndefined(r.error);
                                });
                        }
                    });
                });
            });
        });
    });
});


test.run(console.DEBUG);