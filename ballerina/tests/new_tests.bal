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

import ballerina/test;
import ballerina/crypto;
// import ballerina/io;
// import ballerina/io;

@test:Config {
    groups: ["username_token", "encryption", "signature", "new"]
}
function testUsernameTokenWithSignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    
    string bodyValue = string `<yourPayload>...</yourPayload>`;
    Encryption enc = check new();
    byte[] encryptData = check enc.encryptData(bodyValue, AES_128);
    env.addEncryption(AES_128, encryptData);

    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");
    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, privateKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);
    test:assertEquals(signature, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string buildToken = check env.generateEnvelope();

    byte[] signedData = <byte[]>env.getSignatureData();
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = enc.decryptData(encData, AES_128);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));

    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
    // io:println(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "new"]
}
function testUsernameTokenWithAsymmetricBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    string bodyValue = "<yourPayload>...</yourPayload>";
    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    
    Encryption encrypt = check new();
    byte[] encryptData = check encrypt.encryptData(bodyValue, RSA_ECB, publicKey);

    env.addEncryption(RSA_ECB, encryptData);

    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, privateKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);
    test:assertEquals(signature, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string buildToken = check env.generateEnvelope();


    byte[] signedData = <byte[]>env.getSignatureData();
    crypto:PublicKey receiverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, receiverPublicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = encrypt.decryptData(encData, RSA_ECB, privateKey);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));
    
    // io:println(buildToken);
    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "new"]
}
function testUsernameTokenWithSymmetricBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    string bodyValue = "<yourPayload>...</yourPayload>";
    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");

    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");

    Encryption encrypt = check new();
    byte[] encryptData = check encrypt.encryptData(bodyValue, RSA_ECB, symmetricKey);

    env.addEncryption(RSA_ECB, encryptData);

    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, symmetricKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string buildToken = check env.generateEnvelope();

    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = encrypt.decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));

    test:assertEquals(signature, ());

    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}


@test:Config {
    groups: ["username_token", "encryption", "signature", "x509", "new"]
}
function testUsernameTokenWithX509SignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string bodyValue = " <yourPayload>...</yourPayload> ";
    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    // env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    


    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");

    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");

    Encryption encrypt = check new();
    byte[] encryptData = check encrypt.encryptData(bodyValue, RSA_ECB, symmetricKey);

    env.addEncryption(RSA_ECB, encryptData);

    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, symmetricKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    string buildToken = check env.generateEnvelope();

    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = encrypt.decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));

    test:assertEquals(signature, ());

    assertSignatureWithX509(buildToken);
    assertEncryptedPart(buildToken);

}

@test:Config {
    groups: ["username_token", "signature", "x509"]
}
function testUsernameTokenWithX509Signature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string bodyValue = " <yourPayload>...</yourPayload> ";
    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    // env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/x509_certificate.p12",
        password: "security"
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");

    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    
    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, symmetricKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGNATURE);
    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);
    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    test:assertEquals(signature, ());

    assertSignatureWithX509(buildToken);
    // assertEncryptedPart(buildToken);
}


@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "x509", "new"]
}
function testUsernameTokenWithAsymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    string bodyValue = "<yourPayload>...</yourPayload>";
    crypto:KeyStore serverKeyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey serverPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(serverKeyStore, "wss40", "security");
    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, "wss40");
    
    crypto:KeyStore clientKeyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/x509_certificate.p12",
        password: "security"
    };
    crypto:PrivateKey clientPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(clientKeyStore, "wss40", "security");

    crypto:PublicKey clientPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(clientKeyStore, "wss40");

    Encryption encrypt = check new();
    byte[] encryptData = check encrypt.encryptData(bodyValue, RSA_ECB, serverPublicKey);

    env.addEncryption(RSA_ECB, encryptData);

    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, clientPrivateKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);
    test:assertEquals(signature, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    string buildToken = check env.generateEnvelope();


    byte[] signedData = <byte[]>env.getSignatureData();
    // crypto:PublicKey receiverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = encrypt.decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));
    
    // io:println(buildToken);
    assertSignatureWithX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "x509", "new"]
}
function testUsernameTokenWithSymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    string bodyValue = "<yourPayload>...</yourPayload>";
    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/x509_certificate.p12",
        password: "security"
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");

    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");

    Encryption encrypt = check new();
    byte[] encryptData = check encrypt.encryptData(bodyValue, RSA_ECB, symmetricKey);

    env.addEncryption(RSA_ECB, encryptData);

    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, symmetricKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string buildToken = check env.generateEnvelope();

    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = encrypt.decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));

    test:assertEquals(signature, ());

    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "encryption", "signature"]
}
function testUsernameTokenWithCustomSignatureAndCustomEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    
    string bodyValue = string `<yourPayload>...</yourPayload>`;
    Encryption enc = check new();
    byte[] encryptData = check enc.encryptData(bodyValue, AES_128);
    env.addEncryption(AES_128, encryptData);

    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");
    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA1, privateKey);

    Error? signature = env.addSignature(RSA_SHA1, signData);
    test:assertEquals(signature, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string buildToken = check env.generateEnvelope();

    byte[] signedData = <byte[]>env.getSignatureData();
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    boolean validity = check crypto:verifyRsaSha1Signature(bodyValue.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = enc.decryptData(encData, AES_128);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));

    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "encryption", "aes_256_gcm"]
}
function testUsernameTokenWithEncryptionAES128GCM() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    
    string bodyValue = string `<yourPayload>...</yourPayload>`;
    Encryption enc = check new();
    byte[] encryptData = check enc.encryptData(bodyValue, AES_128);
    env.addEncryption(AES_128, encryptData);

    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");
    // Signature sign = check new();
    // byte[] signData = check sign.signData(bodyValue, RSA_SHA256, privateKey);

    // Error? signature = env.addSignature(RSA_SHA256, signData);
    // test:assertEquals(signature, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, ENCRYPT);
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);
    // byte[] signedData = <byte[]>env.getSignatureData();
    // crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    // boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
    // test:assertTrue(validity);

    byte[] encData = <byte[]>env.getEncData();
    byte[]|Error decryptData = enc.decryptData(encData, AES_128);
    test:assertEquals(bodyValue, check string:fromBytes(check decryptData));

    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string bodyValue = " <yourPayload>...</yourPayload> ";
    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    // env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    crypto:KeyStore keyStore = {
        path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
        password: "security"
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");

    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    
    Signature sign = check new();
    byte[] signData = check sign.signData(bodyValue, RSA_SHA256, symmetricKey);

    Error? signature = env.addSignature(RSA_SHA256, signData);

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGNATURE);
    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);
    byte[] signedData = <byte[]>env.getSignatureData();

    boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    test:assertEquals(signature, ());

    assertSignatureWithX509(buildToken);
    // assertEncryptedPart(buildToken);
}