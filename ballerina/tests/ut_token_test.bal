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

@test:Config {}
function testRequest() returns error? {
    Request request = new();
    string expected = "John";
    request.setUsername(expected);
    test:assertEquals(request.getUsername(), expected);
}

@test:Config {}
function testDocument() returns error? {
    
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" soap:mustUnderstand="true"><wsse:UsernameToken wsu:Id="UsernameToken-5141a9f8-6c18-4c3d-a8b2-27eb5459375d"><wsse:Username>username</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">password</wsse:Password></wsse:UsernameToken></wsse:Security> </soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    
    Document doc = check new(xmlPayload);
    test:assertEquals(check doc.getDocument(), xmlPayload);
}

@test:Config {}
function testWSSecHeader() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" soap:mustUnderstand="true"><wsse:UsernameToken wsu:Id="UsernameToken-5141a9f8-6c18-4c3d-a8b2-27eb5459375d"><wsse:Username>username</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">password</wsse:Password></wsse:UsernameToken></wsse:Security> </soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    
    Document doc = check new(xmlPayload);
    WSSecurityHeader ws = check new(doc);
    error? insertSecHeader = ws.insertSecHeader();
    test:assertEquals(insertSecHeader, ());
}

@test:Config {
    groups: ["username_token"]
}
function testUsernameTokenWithText() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    
    Document doc = check new(xmlPayload);
    WSSecurityHeader ws = check new(doc);
    error? insertSecHeader = ws.insertSecHeader();
    test:assertEquals(insertSecHeader, ());
    UsernameToken userNameToken = new(ws);
    string buildToken = check userNameToken.buildToken("user", "pass", TEXT);

    string begin = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" soap:mustUnderstand="true">`;
    
    string end = string `<wsse:Username>user</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">pass</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    
    test:assertTrue(buildToken.startsWith(begin));
    test:assertTrue(buildToken.endsWith(end));
}

@test:Config {
    groups: ["username_token"]
}
function testUsernameTokenWithDigest() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Document doc = check new(xmlPayload);
    WSSecurityHeader ws = check new(doc);
    error? insertSecHeader = ws.insertSecHeader();
    test:assertEquals(insertSecHeader, ());
    UsernameToken userNameToken = new(ws);
    string buildToken = check userNameToken.buildToken("user", "pass", DIGEST);

    string:RegExp username = re `<wsse:UsernameToken wsu:Id=".*"><wsse:Username>user</wsse:Username>`;
    string:RegExp password = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
    string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;

    test:assertTrue(buildToken.includesMatch(username));
    test:assertTrue(buildToken.includesMatch(password));
    test:assertTrue(buildToken.includesMatch(nonce));
    test:assertTrue(buildToken.includesMatch(created));
}

@test:Config {
    groups: ["username_token", "signature"]
}
function testUsernameTokenWithSignature() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Document doc = check new(xmlPayload);
    WSSecurityHeader ws = check new(doc);
    error? insertSecHeader = ws.insertSecHeader();
    test:assertEquals(insertSecHeader, ());
    UsernameToken userNameToken = new(ws);
    string buildToken = check userNameToken.buildToken("user", "pass", SIGN);

    // verify derived key atrributes in username token
    string:RegExp username = re `<wsse:UsernameToken xmlns:wsse11="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" wsu:Id=".*"><wsse:Username>user</wsse:Username>`;
    string:RegExp salt = re `<wsse11:Salt>.*</wsse11:Salt>`;
    string:RegExp iteration = re `<wsse11:Iteration>1000</wsse11:Iteration>`;

    test:assertTrue(buildToken.includesMatch(username));
    test:assertTrue(buildToken.includesMatch(salt));
    test:assertTrue(buildToken.includesMatch(iteration));

    // verify signature attributes in the security header
    string:RegExp signature = re `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" .*">.*</ds:Signature>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>.*</ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>`;
    string:RegExp transformMethod = re `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`;
    string:RegExp digestMethod = re `<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>`;
    string:RegExp signatureValue = re `<ds:SignatureValue>.*</ds:SignatureValue>`;
    string:RegExp keyIdentifier = re `<wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">.*</wsse:KeyIdentifier>`;
    string:RegExp securityTokenRef = re `<wsse:SecurityTokenReference wsu:Id=".*">.*</wsse:SecurityTokenReference>`;

    test:assertTrue(buildToken.includesMatch(signature));
    test:assertTrue(buildToken.includesMatch(signatureInfo));
    test:assertTrue(buildToken.includesMatch(canonicalizationMethod));
    test:assertTrue(buildToken.includesMatch(signatureMethod));
    test:assertTrue(buildToken.includesMatch(transformMethod));
    test:assertTrue(buildToken.includesMatch(digestMethod));
    test:assertTrue(buildToken.includesMatch(signatureValue));
    test:assertTrue(buildToken.includesMatch(keyIdentifier));
    test:assertTrue(buildToken.includesMatch(securityTokenRef));
}

@test:Config {
    groups: ["username_token", "encryption"]
}
function testUsernameTokenWithEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Document doc = check new(xmlPayload);
    WSSecurityHeader ws = check new(doc);
    error? insertSecHeader = ws.insertSecHeader();
    test:assertEquals(insertSecHeader, ());
    UsernameToken userNameToken = new(ws);
    string buildToken = check userNameToken.buildToken("user", "pass", ENCRYPT);
    
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
    groups: ["username_token", "encryption", "signature"]
}
function testUsernameTokenWithSignatureAndEncryption() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Document doc = check new(xmlPayload);
    WSSecurityHeader ws = check new(doc);
    error? insertSecHeader = ws.insertSecHeader();
    test:assertEquals(insertSecHeader, ());
    UsernameToken userNameToken = new(ws);
    string buildToken = check userNameToken.buildToken("user", "pass", SIGN_AND_ENCRYPT);
    
    // verify signature attributes in the security header
    string:RegExp signature = re `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" .*">.*</ds:Signature>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>.*</ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>`;
    string:RegExp transformMethod = re `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`;
    string:RegExp digestMethod = re `<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>`;
    string:RegExp signatureValue = re `<ds:SignatureValue>.*</ds:SignatureValue>`;
    string:RegExp keyIdentifier = re `<wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">.*</wsse:KeyIdentifier>`;
    string:RegExp securityTokenRef = re `<wsse:SecurityTokenReference wsu:Id=".*">.*</wsse:SecurityTokenReference>`;

    test:assertTrue(buildToken.includesMatch(signature));
    test:assertTrue(buildToken.includesMatch(signatureInfo));
    test:assertTrue(buildToken.includesMatch(canonicalizationMethod));
    test:assertTrue(buildToken.includesMatch(signatureMethod));
    test:assertTrue(buildToken.includesMatch(transformMethod));
    test:assertTrue(buildToken.includesMatch(digestMethod));
    test:assertTrue(buildToken.includesMatch(signatureValue));
    test:assertTrue(buildToken.includesMatch(keyIdentifier));
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
