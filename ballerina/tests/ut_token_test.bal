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

// import ballerina/io;
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
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>`;
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
    string username = "user";
    string password = "password";

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(username, password, TEXT);
    string buildToken = check env.generateEnvelope();
    string:RegExp usernameTokenTag = re `<wsse:UsernameToken wsu:Id=".*">.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${username}</wsse:Username>`;
    string:RegExp passwordTag  = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${password}</wsse:Password>`;

    test:assertTrue(buildToken.includesMatch(usernameTokenTag));
    test:assertTrue(buildToken.includesMatch(usernameTag));
    test:assertTrue(buildToken.includesMatch(passwordTag));
}

@test:Config {
    groups: ["username_token", "passwordDigest"]
}
function testUsernameTokenWithHashedPasword() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string username = "user";
    string password = "password";

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(username, password, DIGEST);
    string buildToken = check env.generateEnvelope();

    string:RegExp usernameTag = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>user</wsse:Username>`;
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
    string username = "user";
    string password = "password";

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(username, password, TEXT, SIGN);
    error? x509Token = env.addX509Token("wss40.properties");
    test:assertEquals(x509Token, ());

    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);

    assertSignatureWithX509(buildToken);
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string username = "user";
    string password = "password";

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(username, password, TEXT, SIGN);
    // env.addX509Token("wss40.properties");
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);

    assertSignatureWithoutX509(buildToken);
}

@test:Config {
    groups: ["username_token", "encryption"]
}
function testUsernameTokenWithEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    string username = "user";
    string password = "password";

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(username, password, DIGEST, ENCRYPT);
    string buildToken = check env.generateEnvelope();

    string:RegExp encryptedData = re `<xenc:EncryptedData.*>`;
    string:RegExp encMethod = re `<xenc:EncryptionMethod Algorithm=".*"/>`;
    string:RegExp keyInfo = re `<ds:KeyInfo xmlns:ds=".*">`;
    string:RegExp derivedKeyInfo = re `<wsc:DerivedKeyToken .*>`;
    string:RegExp secTokenRef = re `<wsse:SecurityTokenReference xmlns:wsse=".*">`;
    string:RegExp cipherData = re `<xenc:CipherData>`;
    string:RegExp cipherValue = re `<xenc:CipherValue>`;

    test:assertTrue(buildToken.includesMatch(encryptedData));
    test:assertTrue(buildToken.includesMatch(encMethod));
    test:assertTrue(buildToken.includesMatch(keyInfo));
    test:assertTrue(buildToken.includesMatch(derivedKeyInfo));
    test:assertTrue(buildToken.includesMatch(secTokenRef));
    test:assertTrue(buildToken.includesMatch(cipherData));
    test:assertTrue(buildToken.includesMatch(cipherValue));
}

@test:Config {
    groups: ["username_token", "encryption", "signature"]
}
function testUsernameTokenWithSignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    string username = "user";
    string password = "password";

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(username, password, DIGEST, SIGN_AND_ENCRYPT);
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);

    // verify signature attributes in the security header
    string:RegExp signature = re `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" .*">.*</ds:Signature>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>.*</ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>`;
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

    // verify the encrypted attributes in the SOAP envelope
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
    groups: ["username_token", "encryption", "signature", "x509"]
}
function testUsernameTokenWithX509SignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    string username = "user";
    string password = "password";
    string certPath = "wss40.properties";

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    env.addUsernameToken(username, password, DIGEST, SIGN_AND_ENCRYPT);
    error? x509Token = env.addX509Token(certPath);
    test:assertEquals(x509Token, ());
    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);

    assertSignatureWithX509(buildToken);
    assertEncryptedPart(buildToken);

}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "x509"]
}
function testUsernameTokenWithSymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    error? symmetricBinding = env.addSymmetricBinding("wss40", "security", "EWJHEF23RJ4", "wss40.properties");
    test:assertEquals(symmetricBinding, ());

    string buildToken = check env.generateEnvelope();
    // io:println(buildToken);

    assertSignatureWithX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenWithSymmetricBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    error? symmetricBinding = env.addSymmetricBinding("wss40", "security", "EWJHEF23RJ4");
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
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());
    string publicKey = "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/publickey.cer";
    string privateKey = "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/wss40_1.pem";

    error? asymmetricBinding = env.addAsymmetricBinding("wss40", "security", privateKey, publicKey);
    test:assertEquals(asymmetricBinding, ());

    string buildToken = check env.generateEnvelope();
    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "x509"]
}
function testUsernameTokenWithAsymmetricBindingWithX509() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    string publicKey = "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/publickey.cer";
    string privateKey = "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/wss40_1.pem";

    error? asymmetricBinding = env.addAsymmetricBinding("wss40", "security", privateKey, publicKey, "wss40.properties");
    test:assertEquals(asymmetricBinding, ());

    string buildToken = check env.generateEnvelope();
    assertSignatureWithoutX509(buildToken);
    assertEncryptedPart(buildToken);
}

@test:Config {
    groups: ["username_token", "signature", "transport_binding"]
}
function testUsernameTokenWithTranportBinding() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string username = "user";
    string password = "password";

    Envelope env = check new(xmlPayload) ;
    error? securityHeader = env.addSecurityHeader();
    test:assertEquals(securityHeader, ());

    error? transportBinding = env.addTransportBinding(username, password, DIGEST, true, 600);
    test:assertEquals(transportBinding, ());

    string buildToken = check env.generateEnvelope();

    string:RegExp usernameTag = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>${username}</wsse:Username>`;
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;

    test:assertTrue(buildToken.includesMatch(usernameTag));
    test:assertTrue(buildToken.includesMatch(passwordTag));
    test:assertTrue(buildToken.includesMatch(nonce));
    test:assertTrue(buildToken.includesMatch(created));

    string:RegExp ts_token = re `<wsu:Timestamp wsu:Id=".*">`;
    string:RegExp createdTag = re `<wsu:Created>.*</wsu:Created>`;
    string:RegExp expires = re `<wsu:Expires>.*</wsu:Expires>`;
    test:assertTrue(buildToken.includesMatch(ts_token));
    test:assertTrue(buildToken.includesMatch(createdTag));
    test:assertTrue(buildToken.includesMatch(expires));
}
