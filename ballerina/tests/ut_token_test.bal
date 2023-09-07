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

@test:Config {
    groups: ["username_token", "password_text"]
}
function testUsernameTokenWithPlaintextPassword() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    UTRecord utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT
    };
    string securedEnvelope = check applyUsernameToken(utRecord);

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
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    UTRecord utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DERIVED_KEY_TEXT
    };
    string securedEnvelope = check applyUsernameToken(utRecord);

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
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    UTRecord utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };
    string securedEnvelope = check applyUsernameToken(utRecord);

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
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    UTRecord utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DERIVED_KEY_DIGEST
    };
    string securedEnvelope = check applyUsernameToken(utRecord);
    
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
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    // generating keys
    crypto:KeyStore signKeyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(signKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey signatureVerifyKey = check crypto:decodeRsaPublicKeyFromTrustStore(signKeyStore, KEY_ALIAS);

    crypto:KeyStore encryptKeyStore = {
        path: X509_KEY_STORE_PATH_2,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey encryptKey = check crypto:decodeRsaPrivateKeyFromKeyStore(encryptKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey decryptKey = check crypto:decodeRsaPublicKeyFromTrustStore(encryptKeyStore, KEY_ALIAS);

    UTSignAndEncrypt utSignAndEncrypt = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        encryptionKey: encryptKey,
        signatureKey: signatureKey
    };
    string securedEnvelope = check applyUTSignAndEncrypt(utSignAndEncrypt);

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, signatureVerifyKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, decryptKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithoutX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "encryption", "signature"]
}
function testUsernameTokenWithCustomSignatureAndEncryption() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    // generating keys
    crypto:KeyStore signKeyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(signKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey signatureVerifyKey = check crypto:decodeRsaPublicKeyFromTrustStore(signKeyStore, KEY_ALIAS);

    crypto:KeyStore encryptKeyStore = {
        path: X509_KEY_STORE_PATH_2,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey encryptKey = check crypto:decodeRsaPrivateKeyFromKeyStore(encryptKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey decryptKey = check crypto:decodeRsaPublicKeyFromTrustStore(encryptKeyStore, KEY_ALIAS);

    UTSignAndEncrypt utSignAndEncrypt = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA1,
        encryptionAlgorithm: RSA_ECB,   
        encryptionKey: encryptKey,
        signatureKey: signatureKey,
        x509Token: X509_PUBLIC_CERT_PATH
    };
    string securedEnvelope = check applyUTSignAndEncrypt(utSignAndEncrypt);

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha1Signature(soapBody.toBytes(), signedData, signatureVerifyKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, decryptKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "encryption", "signature", "x509"]
}
function testUsernameTokenWithX509SignatureAndEncryption() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    // generating keys
    crypto:KeyStore signKeyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(signKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey signatureVerifyKey = check crypto:decodeRsaPublicKeyFromTrustStore(signKeyStore, KEY_ALIAS);

    crypto:KeyStore encryptKeyStore = {
        path: X509_KEY_STORE_PATH_2,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey encryptKey = check crypto:decodeRsaPrivateKeyFromKeyStore(encryptKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey decryptKey = check crypto:decodeRsaPublicKeyFromTrustStore(encryptKeyStore, KEY_ALIAS);

    UTSignAndEncrypt utSignAndEncrypt = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        encryptionKey: encryptKey,
        signatureKey: signatureKey,
        x509Token: X509_PUBLIC_CERT_PATH
    };
    string securedEnvelope = check applyUTSignAndEncrypt(utSignAndEncrypt);

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, signatureVerifyKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, decryptKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testUsernameTokenWithAsymmetricBinding() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    // generating keys
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

    UTAsymmetricBinding utAsymmBinding = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey
    };
    string securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithoutX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "x509"]
}
function testUsernameTokenWithAsymmetricBindingWithX509() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    // generating keys
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

    UTAsymmetricBinding utAsymmBinding = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    string securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenWithSymmetricBinding() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UTSymmetricBinding utSymmetricBinding = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        symmetricKey: symmetricKey
    };
    string securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithoutX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}



@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "x509"]
}
function testUsernameTokenWithSymmetricBindingWithX509() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    crypto:KeyStore keyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    X509Token x509Token = check new (X509_PUBLIC_CERT_PATH);
    UTSymmetricBinding utSymmetricBinding = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        symmetricKey: symmetricKey,
        x509Token: x509Token
    };
    string securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithX509(securedEnvelope);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "encryption", "rsa"]
}
function testUsernameTokenWithEncryptionWithRSA() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);
    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey encryptKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey decryptKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UTEncryption utEncryption = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST,
        encryptionAlgorithm: RSA_ECB,
        encryptionKey: encryptKey
    };
    string securedEnvelope = check applyUTEncryption(utEncryption);
    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, decryptKey);
    test:assertEquals(check string:fromBytes(decryptDataResult), soapBody);
    assertEncryptedPart(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignature() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UTSignature utSignature = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureKey: signatureKey,
        signatureAlgorithm: RSA_SHA256
    };
    string securedEnvelope = check applyUTSignature(utSignature);
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithoutX509(securedEnvelope);
}

@test:Config {
    groups: ["username_token", "signature", "x509"]
}
function testUsernameTokenWithX509Signature() returns error? {
    string envelope = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body><yourPayload>This is the SOAP Body</yourPayload></soap:Body> </soap:Envelope>`;
    string soapBody = check getEnvelopeBody(envelope);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UTSignature utSignature = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureKey: signatureKey,
        signatureAlgorithm: RSA_SHA256,
        x509Token: X509_PUBLIC_CERT_PATH
    };
    string securedEnvelope = check applyUTSignature(utSignature);
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithX509(securedEnvelope);
}
