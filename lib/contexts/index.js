const contextBBSV1 = require('./bbs-bls-signature-2020-v1.json');
const contextCredentialV1 = require('./www.w3.org_2018_credentials_v1.json');
const contextCredentialV2 = require('./www.w3.org_ns_credentials_v2.json');
const contextDidV1 = require('./www.w3.org_ns_did_v1.json');
const contextLdsEcdsaSecpRecovery2020_0 = require('./lds-ecdsa-secp256k1-recovery2020-0.0.json');
const contextSecurityV1 = require('./w3id.org_security_v1.json');
const contextSecurityV2 = require('./w3id.org_security_v2.json');
const contextSecurityV3 = require('./w3id.org_security_v3-unstable.json');
const contextSuiteEip712 = require('./eip712.json');
const contextSuitesEd25519_2018 = require('./w3id.org_security_suites_ed25519-2018_v1.json');
const contextSuitesEd25519_2020 = require('./ed25519-signature-2020-v1.json');
const contextSuitesJws_2020 = require('./json-web-signature-2020-v1.json');
const contextSuitesSecp = require('./w3id.org_security_suites_secp256k1recovery-2020_v2.json');
const contextSuitesX25519 = require('./w3id.org_security_suites_x25519-2019_v1.json');

module.exports = {
  "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld": contextLdsEcdsaSecpRecovery2020_0,
  "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-2.0.jsonld": contextSuitesSecp,
  "https://w3.org/ns/did/v1": contextDidV1,
  "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/": contextSuiteEip712,
  "https://w3id.org/did/v1": contextDidV1,
  "https://w3id.org/security/bbs/v1": contextBBSV1,
  "https://w3id.org/security/suites/ed25519-2018/v1": contextSuitesEd25519_2018,
  "https://w3id.org/security/suites/ed25519-2020/v1": contextSuitesEd25519_2020,
  "https://w3id.org/security/suites/eip712sig-2021": contextSuiteEip712,
  "https://w3id.org/security/suites/jws-2020/v1": contextSuitesJws_2020,
  "https://w3id.org/security/suites/secp256k1recovery-2020/v2": contextSuitesSecp,
  "https://w3id.org/security/suites/x25519-2019/v1": contextSuitesX25519,
  "https://w3id.org/security/v1": contextSecurityV1,
  "https://w3id.org/security/v2": contextSecurityV2,
  "https://w3id.org/security/v3-unstable": contextSecurityV3,
  "https://www.w3.org/2018/credentials/v1": contextCredentialV1,
  "https://www.w3.org/ns/credentials/v2": contextCredentialV2,
  "https://www.w3.org/ns/did/v1": contextDidV1,
};
