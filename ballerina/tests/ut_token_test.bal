// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/crypto;
import ballerina/test;

@test:Config {
    groups: ["username_token", "password_text"]
}
function testUsernameTokenWithPlaintextPassword() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    string securedEnvelope = check env.applyUsernameToken(USERNAME, PASSWORD, TEXT);

    string:RegExp usernameTokenTag = re `<wsse:UsernameToken wsu:Id=".*">.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${PASSWORD}</wsse:Password>`;

    test:assertTrue(securedEnvelope.includesMatch(usernameTokenTag));
    test:assertTrue(securedEnvelope.includesMatch(usernameTag));
    test:assertTrue(securedEnvelope.includesMatch(passwordTag));
}

@test:Config {
    groups: ["username_token", "password_text", "derived_key"]
}
function testUsernameTokenWithPlaintextPasswordWithDerivedKey() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    string securedEnvelope = check env.applyUsernameToken(USERNAME, PASSWORD, DERIVED_KEY_TEXT);

    string:RegExp usernameTokenTag = re `<wsse:UsernameToken .*>.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp salt = re `<wsse11:Salt>.*</wsse11:Salt>`;
    string:RegExp iteration = re `<wsse11:Iteration>.*</wsse11:Iteration>`;

    test:assertTrue(securedEnvelope.includesMatch(usernameTokenTag));
    test:assertTrue(securedEnvelope.includesMatch(usernameTag));
    test:assertTrue(securedEnvelope.includesMatch(salt));
    test:assertTrue(securedEnvelope.includesMatch(iteration));
}

@test:Config {
    groups: ["username_token", "password_digest"]
}
function testUsernameTokenWithHashedPasword() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new (xmlPayload);
    string securedEnvelope = check env.applyUsernameToken(USERNAME, PASSWORD, DIGEST);

    string:RegExp usernameTag = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;

    test:assertTrue(securedEnvelope.includesMatch(usernameTag));
    test:assertTrue(securedEnvelope.includesMatch(passwordTag));
    test:assertTrue(securedEnvelope.includesMatch(nonce));
    test:assertTrue(securedEnvelope.includesMatch(created));
}

@test:Config {
    groups: ["username_token", "password_digest", "derived_key"]
}
function testUsernameTokenWithHashedPaswordWithDerivedKey() returns error? {

    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    string securedEnvelope = check env.applyUsernameToken(USERNAME, PASSWORD, DERIVED_KEY_DIGEST);

    string:RegExp usernameTag = re `<wsse:UsernameToken\s+.*><wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;
    string:RegExp salt = re `<wsse11:Salt>.*</wsse11:Salt>`;
    string:RegExp iteration = re `<wsse11:Iteration>.*</wsse11:Iteration>`;

    test:assertTrue(securedEnvelope.includesMatch(usernameTag));
    test:assertTrue(securedEnvelope.includesMatch(nonce));
    test:assertTrue(securedEnvelope.includesMatch(created));
    test:assertTrue(securedEnvelope.includesMatch(salt));
    test:assertTrue(securedEnvelope.includesMatch(iteration));
}

@test:Config {
    groups: ["username_token", "encryption", "signature", "aes_128"]
}
function testUsernameTokenWithSignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    // generating keys
    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    // encryption
    Encryption enc = check new ();
    byte[] encryptData = check enc.encryptData(soapBody, AES_128);
    Error? encryption = env.addEncryption(AES_128, encryptData);
    test:assertEquals(encryption, ());

    // signing the data
    Signature sign = check new ();
    byte[] signData = check sign.signData(soapBody, RSA_SHA256, privateKey);
    Error? signature = env.addSignature(RSA_SHA256, signData);
    test:assertEquals(signature, ());

    // generating the SOAP envelope
    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string securedEnvelope = check env.generateEnvelope();

    // verifying the process
    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = enc.decryptData(encData, AES_128);
    test:assertEquals(soapBody, check string:fromBytes(check decryptData));

    assertSignatureWithoutX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "encryption", "signature"]
}
function testUsernameTokenWithCustomSignatureAndCustomEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    // Encryption enc = check new ();
    // byte[] encryptData = check enc.encryptData(soapBody, AES_128);
    // Error? encryption = env.addEncryption(AES_128, encryptData);
    // test:assertEquals(encryption, ());

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    // Signature sign = check new ();
    // byte[] signData = check sign.signData(soapBody, RSA_SHA1, privateKey);

    // Error? signature = env.addSignature(RSA_SHA1, signData);
    // test:assertEquals(signature, ());

    // env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string securedEnvelope = check env.applyUTSignAndEncrypt(USERNAME, PASSWORD, TEXT, privateKey,
                                                       RSA_SHA1, publicKey, AES_128, ());

    byte[] signedData = <byte[]>env.getSignatureData();
    boolean validity = check crypto:verifyRsaSha1Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = env.decryptData(encData, AES_128);
    test:assertEquals(soapBody, check string:fromBytes(check decryptData));

    assertSignatureWithoutX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "encryption", "signature", "x509"]
}
function testUsernameTokenWithX509SignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;

    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    crypto:KeyStore keyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);

    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    Encryption encrypt = check new ();
    byte[] encryptData = check encrypt.encryptData(soapBody, RSA_ECB, symmetricKey);

    Error? encryption = env.addEncryption(RSA_ECB, encryptData);
    test:assertEquals(encryption, ());

    Signature sign = check new ();
    byte[] signData = check sign.signData(soapBody, RSA_SHA256, symmetricKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    test:assertEquals(x509Token, ());

    string securedEnvelope = check env.generateEnvelope();

    byte[] signedData = <byte[]>env.getSignatureData();
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = encrypt.decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(check decryptData));
    test:assertEquals(signature, ());
    assertSignatureWithX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);

}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testUsernameTokenWithAsymmetricBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;

    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    // generating keys
    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    string securedEnvelope = check env.applyAsymmetricBinding(USERNAME, PASSWORD, privateKey, publicKey, RSA_ECB, RSA_SHA256);

    byte[] signedData = <byte[]>env.getSignatureData();
    crypto:PublicKey receiverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, receiverPublicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = env.decryptData(encData, RSA_ECB, privateKey);
    test:assertEquals(soapBody, check string:fromBytes(check decryptData));

    assertSignatureWithoutX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "x509"]
}
function testUsernameTokenWithAsymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    crypto:KeyStore serverKeyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey serverPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(serverKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

    crypto:KeyStore clientKeyStore = {
        path: X509_KEY_STORE_PATH_2,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey clientPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(clientKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey clientPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(clientKeyStore, KEY_ALIAS);

    X509Token x509Token = check new (X509_PUBLIC_CERT_PATH_2);
    string securedEnvelope = check env.applyAsymmetricBinding(USERNAME, PASSWORD, clientPrivateKey, serverPublicKey, RSA_ECB, RSA_SHA256, x509Token);

    byte[] signedData = <byte[]>env.getSignatureData();
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = env.decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(check decryptData));

    assertSignatureWithX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenWithSymmetricBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    string securedEnvelope = check env.applySymmetricBinding(USERNAME, PASSWORD, symmetricKey, RSA_ECB, RSA_SHA256);
    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = env.decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(check decryptData));

    assertSignatureWithoutX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "x509"]
}
function testUsernameTokenWithSymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    crypto:KeyStore keyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    X509Token x509Token = check new (X509_PUBLIC_CERT_PATH);
    string securedEnvelope = check env.applySymmetricBinding(USERNAME, PASSWORD, symmetricKey, RSA_ECB, RSA_SHA256, x509Token);

    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = env.decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(check decryptData));

    assertSignatureWithX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "encryption", "aes_256_gcm"]
}
function testUsernameTokenWithEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    
    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    string securedEnvelope = check env.applyUTEncryption(USERNAME, PASSWORD, AES_128);
    byte[] encData = <byte[]>env.getEncryptedData();
    byte[]|Error decryptData = env.decryptData(encData, AES_128);
    test:assertEquals(check string:fromBytes(check decryptData), soapBody);

    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "x509"]
}
function testUsernameTokenWithX509Signature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    crypto:KeyStore keyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    X509Token x509Token = check new (X509_PUBLIC_CERT_PATH);
    string securedEnvelope = check env.applyUTSignature(USERNAME, PASSWORD, DIGEST, RSA_SHA256, privateKey, x509Token);

    byte[] signedData = <byte[]>env.getSignatureData();
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);
    assertSignatureWithX509(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    Envelope env = check new (xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string soapBody = check env.getEnvelopeBody();

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    string securedEnvelope = check env.applyUTSignature(USERNAME, PASSWORD, TEXT, RSA_SHA256, privateKey);

    byte[] signedData = <byte[]>env.getSignatureData();
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);
    assertSignatureWithoutX509(securedEnvelope);
}
