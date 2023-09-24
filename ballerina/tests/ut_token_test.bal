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
    assertUsernameToken(envelopeString, TEXT);
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

    assertUsernameToken(envelopeString, DERIVED_KEY_TEXT);
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

    assertUsernameToken(envelopeString, DIGEST);
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

    assertUsernameToken(envelopeString, DERIVED_KEY_DIGEST);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "qw"]
}
function testSymmetricBindingPolicyWithSignatureOnly() returns error? {
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

    SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        symmetricKey: symmetricKey
    };
    
    xml securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithoutX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "qw"]
}
function testSymmetricBindingPolicyWithX509SignatureOnly() returns error? {
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

    SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        symmetricKey: symmetricKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    
    xml securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    assertSignatureWithX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testSymmetricBindingPolicyEncryptionOnly() returns error? {
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

    SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey
    };
    
    xml securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testSymmetricBindingWithSignatureAndEncryption() returns error? {
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

    SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey
    };
    xml securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
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
    groups: ["username_token", "signature", "symmetric_binding", "q"]
}
function testSymmetricBindingPolicyWithX509SignatureAndEncryption() returns error? {
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

    SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    
    xml securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
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

    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };

    envelope = check applyUsernameToken(utRecord);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        symmetricKey: symmetricKey
    };
    xml securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertUsernameToken(envelopeString, DIGEST);
    assertSignatureWithoutX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenTimestampWithSymmetricBindingAndX509Token() returns error? {
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

    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };

    envelope = check applyUsernameToken(utRecord);
    
    envelope = check applyTimestampToken(envelope = envelope, timeToLive = 600);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    SymmetricBindingConfig utSymmetricBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    
    xml securedEnvelope = check applySymmetricBinding(utSymmetricBinding);
    string envelopeString = securedEnvelope.toBalString();
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, publicKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertUsernameToken(envelopeString, DIGEST);
    assertTimestampToken(envelopeString);
    assertSignatureWithoutX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testAsymmetricBindingWithSignature() returns error? {
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
    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

    crypto:KeyStore clientKeyStore = {
        path: X509_KEY_STORE_PATH_2,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey clientPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(clientKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey clientPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(clientKeyStore, KEY_ALIAS);

    AsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,  
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey
    };
    xml securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    assertSignatureWithoutX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testAsymmetricBindingWithX509Signature() returns error? {
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
    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

    crypto:KeyStore clientKeyStore = {
        path: X509_KEY_STORE_PATH_2,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey clientPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(clientKeyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey clientPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(clientKeyStore, KEY_ALIAS);

    AsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,  
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    xml securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    assertSignatureWithX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testAsymmetricBindingWithEncryption() returns error? {
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

    AsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey
    };
    xml securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testAsymmetricBindingWithSignatureAndEncryption() returns error? {
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

    AsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey
    };
    xml securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);
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
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testAsymmetricBindingWithX509SignatureAndEncryption() returns error? {
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

    AsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    xml securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);
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
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testUsernameTokenWithAsymmetricBindingAndX509() returns error? {
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

    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };

    envelope = check applyUsernameToken(utRecord);
    
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

    AsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    xml securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertUsernameToken(envelopeString, DIGEST);
    assertSignatureWithX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "n"]
}
function testUsernameTokenTimestampWithAsymmetricBindingAndX509() returns error? {
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

    UsernameTokenConfig utRecord = {
        envelope: envelope,
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };

    envelope = check applyUsernameToken(utRecord);
    
    envelope = check applyTimestampToken(envelope = envelope, timeToLive = 600);
    
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

    AsymmetricBindingConfig utAsymmBinding = {
        envelope: envelope,
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,   
        receiverPublicKey: serverPublicKey, 
        senderPrivateKey: clientPrivateKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };
    xml securedEnvelope = check applyAsymmetricBinding(utAsymmBinding);
    string envelopeString = securedEnvelope.toBalString();

    byte[] signedData = check getSignatureData(securedEnvelope);
    boolean validity = check crypto:verifyRsaSha256Signature(soapBody.toBytes(), signedData, clientPublicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check decryptData(encData, RSA_ECB, serverPrivateKey);
    test:assertEquals(soapBody, check string:fromBytes(decryptDataResult));

    assertUsernameToken(envelopeString, DIGEST);
    assertTimestampToken(envelopeString);
    assertSignatureWithX509(envelopeString);
    assertEncryptedPart(envelopeString);
}
