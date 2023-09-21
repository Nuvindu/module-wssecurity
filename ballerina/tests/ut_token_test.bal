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
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT
    };
    xml securedEnvelope = check applyUsernameToken(utRecord);
    string envelopeString = securedEnvelope.toBalString();
    string:RegExp usernameTokenTag = re `<wsse:UsernameToken wsu:Id=".*">.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${PASSWORD}</wsse:Password>`;

    test:assertTrue(envelopeString.includesMatch(usernameTokenTag));
    test:assertTrue(envelopeString.includesMatch(usernameTag));
    test:assertTrue(envelopeString.includesMatch(passwordTag));
}

@test:Config {
    groups: ["username_token", "password_text", "derived_key"]
}
function testUsernameTokenWithPlaintextPasswordWithDerivedKey() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DERIVED_KEY_TEXT
    };
    xml securedEnvelope = check applyUsernameToken(utRecord);
    string envelopeString = securedEnvelope.toBalString();

    string:RegExp usernameTokenTag = re `<wsse:UsernameToken .*>.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp salt = re `<wsse11:Salt>.*</wsse11:Salt>`;
    string:RegExp iteration = re `<wsse11:Iteration>.*</wsse11:Iteration>`;

    test:assertTrue(envelopeString.includesMatch(usernameTokenTag));
    test:assertTrue(envelopeString.includesMatch(usernameTag));
    test:assertTrue(envelopeString.includesMatch(salt));
    test:assertTrue(envelopeString.includesMatch(iteration));
}

@test:Config {
    groups: ["username_token", "password_digest"]
}
function testUsernameTokenWithHashedPasword() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };
    xml securedEnvelope = check applyUsernameToken(utRecord);
    string envelopeString = securedEnvelope.toBalString();

    string:RegExp usernameTag = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;

    test:assertTrue(envelopeString.includesMatch(usernameTag));
    test:assertTrue(envelopeString.includesMatch(passwordTag));
    test:assertTrue(envelopeString.includesMatch(nonce));
    test:assertTrue(envelopeString.includesMatch(created));
}

@test:Config {
    groups: ["username_token", "password_digest", "derived_key"]
}
function testUsernameTokenWithHashedPaswordWithDerivedKey() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DERIVED_KEY_DIGEST
    };
    xml securedEnvelope = check applyUsernameToken(utRecord);
    string envelopeString = securedEnvelope.toBalString();

    string:RegExp usernameTag = re `<wsse:UsernameToken\s+.*><wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;
    string:RegExp salt = re `<wsse11:Salt>.*</wsse11:Salt>`;
    string:RegExp iteration = re `<wsse11:Iteration>.*</wsse11:Iteration>`;
    
    test:assertTrue(envelopeString.includesMatch(usernameTag));
    test:assertTrue(envelopeString.includesMatch(nonce));
    test:assertTrue(envelopeString.includesMatch(created));
    test:assertTrue(envelopeString.includesMatch(salt));
    test:assertTrue(envelopeString.includesMatch(iteration));
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testUsernameTokenWithAsymmetricBinding() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
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

    UtAsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey
    };
    xml securedEnvelope = check applyUtAsymmetricBinding(utAsymmBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithoutX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "x509"]
}
function testX509TokenWithAsymmetricBinding() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
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

    X509AsymmetricBindingConfig utAsymmBinding = {
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
    xml securedEnvelope = check applyX509AsymmetricBinding(utAsymmBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));
    assertSignatureWithX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenWithSymmetricBinding() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    string soapBody = check getEnvelopeBody(envelope);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UtSymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        symmetricKey: symmetricKey
    };
    xml securedEnvelope = check applyUtSymmetricBinding(utSymmetricBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithoutX509(envelopeString);
    assertEncryptedPart(envelopeString);
}



@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "x509"]
}
function testX509TokenWithSymmetricBinding() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    string soapBody = check getEnvelopeBody(envelope);

    crypto:KeyStore keyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    X509Token x509Token = check new (X509_PUBLIC_CERT_PATH);
    X509SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        symmetricKey: symmetricKey,
        x509Token: x509Token
    };
    xml securedEnvelope = check applyX509SymmetricBinding(utSymmetricBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertSignatureWithX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "encryption", "rsa"]
}
function testUsernameTokenWithEncryptionWithRSA() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    string soapBody = check getEnvelopeBody(envelope);
    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey encryptKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey decryptKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UtEncryptionConfig utEncryption = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST,
        encryptionAlgorithm: RSA_ECB,
        encryptionKey: encryptKey
    };
    xml securedEnvelope = check applyUtEncryption(utEncryption);
    string envelopeString = securedEnvelope.toBalString();

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, decryptKey);
    test:assertEquals(check string:fromBytes(decryptDataResult), soapBody);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignatureRsaSha1() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UtSignatureConfig utSignature = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureKey: signatureKey,
        signatureAlgorithm: RSA_SHA1
    };
    xml securedEnvelope = check applyUtSignature(utSignature);
    string envelopeString = securedEnvelope.toBalString();
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha1Signature(envelope.toBalString().toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithoutX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignatureRsaSha256() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UtSignatureConfig utSignature = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureKey: signatureKey,
        signatureAlgorithm: RSA_SHA256
    };
    xml securedEnvelope = check applyUtSignature(utSignature);
    string envelopeString = securedEnvelope.toBalString();
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(envelope.toBalString().toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithoutX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignatureRsaSha384() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UtSignatureConfig utSignature = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureKey: signatureKey,
        signatureAlgorithm: RSA_SHA384
    };
    xml securedEnvelope = check applyUtSignature(utSignature);
    string envelopeString = securedEnvelope.toBalString();
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha384Signature(envelope.toBalString().toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithoutX509(envelopeString);
}
@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignatureRsaSha512() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    UtSignatureConfig utSignature = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureKey: signatureKey,
        signatureAlgorithm: RSA_SHA512
    };
    xml securedEnvelope = check applyUtSignature(utSignature);
    string envelopeString = securedEnvelope.toBalString();
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha512Signature(envelope.toBalString().toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithoutX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "x509"]
}
function testX509TokenWithSignature() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    string soapBody = check getEnvelopeBody(envelope);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey signatureKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    X509SignatureConfig utSignature = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT,
        signatureKey: signatureKey,
        signatureAlgorithm: RSA_SHA256,
        x509Token: X509_PUBLIC_CERT_PATH
    };
    xml securedEnvelope = check applyX509Signature(utSignature);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithX509(envelopeString);
}
