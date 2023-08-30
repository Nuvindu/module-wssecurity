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

function assertSignatureWithX509(string buildToken) {
    string:RegExp keyIdentifier = re `<wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">.*</wsse:KeyIdentifier>`;
    test:assertTrue(buildToken.includesMatch(keyIdentifier));
    assertSignatureWithoutX509(buildToken);
}

function assertSignatureWithoutX509(string buildToken) {
    string:RegExp signature = re `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" .*">.*</ds:Signature>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>.*</ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm=".*"/>`;
    string:RegExp transformMethod = re `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`;
    string:RegExp digestMethod = re `<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>`;
    string:RegExp signatureValue = re `<ds:SignatureValue>.*</ds:SignatureValue>`;
   
    string:RegExp securityTokenRef = re `<wsse:SecurityTokenReference wsu:Id=".*">.*</wsse:SecurityTokenReference>`;

    test:assertTrue(buildToken.includesMatch(signature));
    test:assertTrue(buildToken.includesMatch(signatureInfo));
    test:assertTrue(buildToken.includesMatch(canonicalizationMethod));
    test:assertTrue(buildToken.includesMatch(signatureMethod));
    test:assertTrue(buildToken.includesMatch(transformMethod));
    test:assertTrue(buildToken.includesMatch(digestMethod));
    test:assertTrue(buildToken.includesMatch(signatureValue));
    test:assertTrue(buildToken.includesMatch(securityTokenRef));
}

function assertEncryptedPart(string buildToken) {
    string:RegExp encryptedData = re `<xenc:EncryptedData.*</xenc:EncryptedData>`;
    string:RegExp encMethod = re `<xenc:EncryptionMethod Algorithm=".*"/>`;
    string:RegExp keyInfo = re `<ds:KeyInfo xmlns:ds=".*">.*</ds:KeyInfo>`;
    string:RegExp derivedKeyInfo = re `<wsc:DerivedKeyToken .*>.*</wsc:DerivedKeyToken>`;
    string:RegExp secTokenRef = re `<wsse:SecurityTokenReference xmlns:wsse=".*">.*</wsse:SecurityTokenReference>`;
    string:RegExp cipherData = re `<xenc:CipherData>.*</xenc:CipherData>`;
    string:RegExp cipherValue = re `<xenc:CipherValue>.*</xenc:CipherValue>`;

    test:assertTrue(buildToken.includesMatch(encryptedData));
    test:assertTrue(buildToken.includesMatch(encMethod));
    test:assertTrue(buildToken.includesMatch(keyInfo));
    test:assertTrue(buildToken.includesMatch(derivedKeyInfo));
    test:assertTrue(buildToken.includesMatch(secTokenRef));
    test:assertTrue(buildToken.includesMatch(cipherData));
    test:assertTrue(buildToken.includesMatch(cipherValue));
}

@test:Config {
    groups: ["username_token", "passwordText"]
}
function testUsernameTokenWithPlaintextPassword() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, TEXT);
    string buildToken = check env.generateEnvelope();
    
    string:RegExp usernameTokenTag = re `<wsse:UsernameToken wsu:Id=".*">.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp passwordTag  = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${PASSWORD}</wsse:Password>`;

    test:assertTrue(buildToken.includesMatch(usernameTokenTag));
    test:assertTrue(buildToken.includesMatch(usernameTag));
    test:assertTrue(buildToken.includesMatch(passwordTag));
}

@test:Config {
    groups: ["username_token", "passwordDigest"]
}
function testUsernameTokenWithHashedPasword() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST);
    string buildToken = check env.generateEnvelope();

    string:RegExp usernameTag = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;

    test:assertTrue(buildToken.includesMatch(usernameTag));
    test:assertTrue(buildToken.includesMatch(passwordTag));
    test:assertTrue(buildToken.includesMatch(nonce));
    test:assertTrue(buildToken.includesMatch(created));
}

// @test:Config {
//     groups: ["username_token"]
// }
// function testUsernameTokenWithPlaintextPasswordAndDerivedKey() returns error? {}

@test:Config {
    groups: ["username_token", "signature", "x509"]
}
function testUsernameTokenWithX509Signature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, TEXT, SIGNATURE);
    error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    test:assertEquals(x509Token, ());

    string buildToken = check env.generateEnvelope();
    assertSignatureWithX509(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "d"]
}
function testUsernameTokenWithSignature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, TEXT, SIGNATURE);
    string buildToken = check env.generateEnvelope();
    assertSignatureWithoutX509(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "hmac_512"]
}
function testUsernameTokenWithSignatureHMACSHA512() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, TEXT, SIGNATURE);
    env.addUTSignatureAlgorithm(HMAC_SHA512);
    string buildToken = check env.generateEnvelope();
    assertSignatureWithoutX509(buildToken);
}

@test:Config {
    groups: ["username_token", "encryption"]
}
function testUsernameTokenWithEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, ENCRYPT);
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);
    assertEncryptedPart(buildToken);
}

// @test:Config {
//     groups: ["username_token", "decryption", "q"]
// }
// function testUsernameTokenWithDecryption() returns error? {
//     string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" soap:mustUnderstand="true"><wsc:DerivedKeyToken xmlns:wsc="http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512" wsu:Id="DK-b7dc3d1a-3d50-4115-8311-620eabcf43f4"><wsse:SecurityTokenReference xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" wsse11:TokenType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey" wsu:Id="STR-4fa11bd7-097b-407f-b4cf-f83426d6921f"><wsse:Reference URI="#null"/></wsse:SecurityTokenReference><wsc:Offset>0</wsc:Offset><wsc:Length>16</wsc:Length><wsc:Nonce>kJBe2zvu/yFttai0NVa0vQ==</wsc:Nonce></wsc:DerivedKeyToken><xenc:ReferenceList xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:DataReference URI="#ED-66c68d42-349a-4e97-8e2a-92430af86e3d"/></xenc:ReferenceList><wsse:UsernameToken wsu:Id="UsernameToken-f5ca68f8-08ef-411b-a098-817d7c8b11a7"><wsse:Username>username</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">51iYzBzporhAPUsrlTvfqj3hSL4=</wsse:Password><wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">O4VN64AAG3kmg16NKkxQ4w==</wsse:Nonce><wsu:Created>2023-08-30T13:11:46.742Z</wsu:Created></wsse:UsernameToken></wsse:Security></soap:Header> <soap:Body><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="ED-66c68d42-349a-4e97-8e2a-92430af86e3d" Type="http://www.w3.org/2001/04/xmlenc#Content"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wsse:Reference URI="#DK-b7dc3d1a-3d50-4115-8311-620eabcf43f4" ValueType="http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk"/></wsse:SecurityTokenReference></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>9p+lulgpv0ONs3Klsbg4tqeKDCZF26xM4lPFxTwuFn7Lo1zqim9VtD1tLuIp9NSj8yPM2Zs1aJtd6/F9</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></soap:Body> </soap:Envelope>`;

//     Envelope env = check new(xmlPayload);
//     Error? securityHeader = env.addSecurityHeader();
//     test:assertEquals(securityHeader, ());

//     env.addUsernameToken(USERNAME, PASSWORD, DIGEST, DECRYPT);
//     string buildToken = check env.generateEnvelope();

//     assertEncryptedPart(buildToken);
// }

@test:Config {
    groups: ["username_token", "encryption", "aes_256_gcm"]
}
function testUsernameTokenWithEncryptionAES256GCM() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, ENCRYPT);
    env.addUTEncryptionAlgorithm(AES_256_GCM);
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "encryption", "signature"]
}
function testUsernameTokenWithSignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    string buildToken = check env.generateEnvelope();

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

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    env.addUTSignatureAlgorithm(HMAC_SHA384);
    env.addUTEncryptionAlgorithm(AES_192);
    string buildToken = check env.generateEnvelope();

    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "encryption", "signature", "x509"]
}
function testUsernameTokenWithX509SignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    test:assertEquals(x509Token, ());
    string buildToken = check env.generateEnvelope();

    assertSignatureWithX509(buildToken);
    assertEncryptedPart(buildToken);

}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "x509"]
}
function testUsernameTokenWithSymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    Error? symmetricBinding = env.addSymmetricBinding(USERNAME, PASSWORD, X509_PUBLIC_CERT_PATH);
    test:assertEquals(symmetricBinding, ());

    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    test:assertEquals(x509Token, ());

    string buildToken = check env.generateEnvelope();

    assertSignatureWithX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenWithSymmetricBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    Error? symmetricBinding = env.addSymmetricBinding(USERNAME, PASSWORD, X509_PUBLIC_CERT_PATH);
    test:assertEquals(symmetricBinding, ());

    string buildToken = check env.generateEnvelope();
    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "a"]
}
function testUsernameTokenWithAsymmetricBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    Error? asymmetricBinding = env.addAsymmetricBinding(USERNAME, PASSWORD, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH);
    test:assertEquals(asymmetricBinding, ());

    string buildToken = check env.generateEnvelope();
    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "x509", "b"]
}
function testUsernameTokenWithAsymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    Error? asymmetricBinding = env.addAsymmetricBinding(USERNAME, PASSWORD, PRIVATE_KEY_PATH, X509_PUBLIC_CERT_PATH);
    test:assertEquals(asymmetricBinding, ());

    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    test:assertEquals(x509Token, ());

    string buildToken = check env.generateEnvelope();
    assertSignatureWithX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "x509", "b"]
}
function testMultipleBindings() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    Error? asymmetricBinding = env.addAsymmetricBinding(USERNAME, PASSWORD, PRIVATE_KEY_PATH, X509_PUBLIC_CERT_PATH);
    test:assertEquals(asymmetricBinding, ());

    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    test:assertEquals(x509Token, ());

    // Envelope env = check new(xmlPayload);
    // Error? securityHeader = env.addSecurityHeader();
    // test:assertEquals(securityHeader, ());

    Error? symmetricBinding = env.addSymmetricBinding(USERNAME, PASSWORD, X509_PUBLIC_CERT_PATH);
    test:assertEquals(symmetricBinding, ());

    string buildToken = check env.generateEnvelope();
    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);

    // string buildToken = check env.generateEnvelope();
    // assertSignatureWithX509(buildToken);
    // assertEncryptedPart(buildToken);
}

// @test:Config {
//     groups: ["username_token", "signature", "transport_binding"]
// }
// function testUsernameTokenWithTransportBinding() returns error? {
//     string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
//     string username = "user";
//     string password = "password";

//     Envelope env = check new(xmlPayload) ;
//     Error? securityHeader = env.addSecurityHeader();
//     http:ListenerConfiguration listenerConfig = {
//         secureSocket: {
            
//         }
//     };
//     Error? transportBinding = check env.addTransportBinding(username, password, DIGEST, true, 600);
//     test:assertEquals(transportBinding, ());

//     string buildToken = check env.generateEnvelope();

//     string:RegExp usernameTag = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>${username}</wsse:Username>`;
//     string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
//     string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
//     string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;

//     test:assertTrue(buildToken.includesMatch(usernameTag));
//     test:assertTrue(buildToken.includesMatch(passwordTag));
//     test:assertTrue(buildToken.includesMatch(nonce));
//     test:assertTrue(buildToken.includesMatch(created));

//     string:RegExp ts_token = re `<wsu:Timestamp wsu:Id=".*">`;
//     string:RegExp createdTag = re `<wsu:Created>.*</wsu:Created>`;
//     string:RegExp expires = re `<wsu:Expires>.*</wsu:Expires>`;
//     test:assertTrue(buildToken.includesMatch(ts_token));
//     test:assertTrue(buildToken.includesMatch(createdTag));
//     test:assertTrue(buildToken.includesMatch(expires));
// }

@test:Config {
    groups: ["error"]
}
function testRemoveSecurityPolicies() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    Error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    Error? asymmetricBinding = env.addAsymmetricBinding(USERNAME, PASSWORD, PRIVATE_KEY_PATH, X509_PUBLIC_CERT_PATH);
    test:assertEquals(asymmetricBinding, ());

    Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
    test:assertEquals(x509Token, ());

    Error? removeWSSecurityPolicy = env.removeWSSecurityPolicy(ASYMMETRIC_BINDING);
    test:assertEquals(removeWSSecurityPolicy, ());
    string buildToken = check env.generateEnvelope();

    string:RegExp usernameTag = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>${USERNAME}</wsse:Username>`;
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;

    test:assertTrue(buildToken.includesMatch(usernameTag));
    test:assertTrue(buildToken.includesMatch(passwordTag));
    test:assertTrue(buildToken.includesMatch(nonce));
    test:assertTrue(buildToken.includesMatch(created));
}

@test:Config {
    groups: ["error"]
}
function testNoPolicyError() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    string|Error policyError = env.generateEnvelope();
    error expectedError = error( "WS Security Policy headers are not set.");
    test:assertTrue(policyError is Error);
    if policyError is Error {
        test:assertEquals(policyError.message(), expectedError.message());
    }
}

@test:Config {
    groups: ["error", "username_token", "x509"]
}
function testUTDoesNotExistError() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string x509certPath = "/Users/nuvindu/Ballerina/crypto/src/main/resources/certificate.crt";
    string expectedErrorMessage = "Username Token does not exist.";
    error expectedErrorCause = error("Currently, X509 token is depended on the username token");
    Envelope env = check new(xmlPayload); 
    X509Token|Error x509Token = new(x509certPath);
    test:assertTrue(x509Token !is Error);
    Error? x509TokenResult = env.addX509Token(x509certPath);
    test:assertTrue(x509TokenResult !is ());
    if x509TokenResult is Error {
        test:assertEquals(x509TokenResult.message(), expectedErrorMessage);
        test:assertEquals((<error>x509TokenResult.cause()).message(), expectedErrorCause.message());
    }
}
