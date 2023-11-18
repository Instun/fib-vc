const test = require('test');
test.setup();

const fs = require('fs');
const path = require('path');
const vc = require("../lib");

const keys = fs.readdir(path.join(__dirname, "./data/keys")).map(key => path.basename(key, ".json"));
const credentials = fs.readdir(path.join(__dirname, "./data/credentials")).map(credential => path.basename(credential, ".json"));
const presentations = fs.readdir(path.join(__dirname, "./data/presentations")).map(presentation => path.basename(presentation, ".json"));
const impls = fs.readdir(path.join(__dirname, "./data/implementations"));

describe("vc", () => {
    describe("issue/verify", () => {
        credentials.forEach(credential => {
            const credentialJson = require(`./data/credentials/${credential}.json`);
            keys.forEach(key => {
                const keyJson = require(`./data/keys/${key}.json`);
                it(`${credential}--${key}`, () => {
                    var vcJson = vc.credential.issue({
                        credential: credentialJson,
                        date: credentialJson.issuanceDate,
                        id: keyJson.id,
                        key: keyJson.privateKeyJwk
                    });

                    var r = vc.credential.verify({
                        credential: vcJson,
                        key: keyJson
                    });

                    assert.isTrue(r.verified);

                    vcJson.credentialSubject.fake = "fake";
                    var r = vc.credential.verify({
                        credential: vcJson,
                        key: keyJson
                    });
                    delete vcJson.credentialSubject.fake;
                    assert.equal(r.verified, false);
                });
            });
        });
    });

    describe("implementations", () => {
        impls.forEach(impl => {
            describe(`${impl}`, () => {
                credentials.forEach(credential => {
                    const credentialJson = require(`./data/credentials/${credential}.json`);
                    keys.forEach(key => {
                        const keyJson = require(`./data/keys/${key}.json`);
                        if (fs.exists(path.join(__dirname, `./data/implementations/${impl}/${credential}--${key}.vc.json`)))
                            it(`${credential}--${key}`, () => {
                                const vcJson = require(`./data/implementations/${impl}/${credential}--${key}.vc.json`);

                                var r = vc.credential.verify({
                                    credential: vcJson,
                                    key: keyJson
                                });
                                assert.isTrue(r.verified);

                                vcJson.credentialSubject.fake = "fake";
                                var r = vc.credential.verify({
                                    credential: vcJson,
                                    key: keyJson
                                });
                                delete vcJson.credentialSubject.fake;
                                assert.equal(r.verified, false);
                            });
                    });
                });
            });
        });
    });
});

describe("vp", () => {
    describe("issue/verify", () => {
        presentations.forEach(presentation => {
            const presentationJson = require(`./data/presentations/${presentation}.json`);
            keys.forEach(key => {
                const keyJson = require(`./data/keys/${key}.json`);
                it(`${presentation}--${key}`, () => {
                    var vcJson = vc.presentation.issue({
                        presentation: presentationJson,
                        date: presentationJson.issuanceDate,
                        id: keyJson.id,
                        key: keyJson.privateKeyJwk
                    });

                    var r = vc.presentation.verify({
                        presentation: vcJson,
                        key: keyJson
                    });

                    assert.isTrue(r.verified);

                    vcJson.fake = "fake";
                    var r = vc.presentation.verify({
                        presentation: vcJson,
                        key: keyJson
                    });
                    delete vcJson.fake;
                    assert.equal(r.verified, false);
                });
            });
        });
    });

    describe("implementations", () => {
        impls.forEach(impl => {
            describe(`${impl}`, () => {
                presentations.forEach(presentation => {
                    const presentationJson = require(`./data/presentations/${presentation}.json`);
                    keys.forEach(key => {
                        const keyJson = require(`./data/keys/${key}.json`);
                        if (fs.exists(path.join(__dirname, `./data/implementations/${impl}/${presentation}--${key}.vp.json`)))
                            it(`${presentation}--${key}`, () => {
                                const vcJson = require(`./data/implementations/${impl}/${presentation}--${key}.vp.json`);

                                var r = vc.presentation.verify({
                                    presentation: vcJson,
                                    key: keyJson
                                });
                                assert.isTrue(r.verified);

                                vcJson.fake = "fake";
                                var r = vc.presentation.verify({
                                    presentation: vcJson,
                                    key: keyJson
                                });
                                delete vcJson.fake;
                                assert.equal(r.verified, false);
                            });
                    });
                });
            });
        });
    });
});

test.run(console.DEBUG);