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

const string USERNAME = "username";
const string PASSWORD = "password";

const string KEY_ALIAS = "wss40";
const string KEY_PASSWORD = "security";

const string PUBLIC_KEY_PATH = "tests/resources/public_key.cer";
const string PRIVATE_KEY_PATH = "tests/resources/private_key.pem";
const string KEY_STORE_PATH =  "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12";
const string X509_PUBLIC_CERT_PATH = "tests/resources/x509_certificate.crt";
const string X509_PUBLIC_CERT_PATH_2 = "tests/resources/x509_certificate_2.crt";
const string X509_KEY_STORE_PATH = "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/x509_certificate.p12";
const string X509_KEY_STORE_PATH_2 = "/Users/nuvindu/Ballerina/soap/module-wssecurity/ballerina/tests/resources/x509_certificate_2.p12";

function assertSignatureWithX509(string buildToken) {
    string:RegExp keyIdentifier = re `<wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">.*</wsse:KeyIdentifier>`;
    test:assertTrue(buildToken.includesMatch(keyIdentifier));
    assertSignatureWithoutX509(buildToken);
}

function assertSignatureWithoutX509(string buildToken) {
    string:RegExp signature = re `<ds:Signature xmlns:ds=".*" .*">.*</ds:Signature>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>.*</ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm=".*">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm=".*"/>`;
    string:RegExp transformMethod = re `<ds:Transform Algorithm=".*"/>`;
    string:RegExp digestMethod = re `<ds:DigestMethod Algorithm=".*"/>`;
    string:RegExp signatureValue = re `<ds:SignatureValue>.*</ds:SignatureValue>`;
   
    string:RegExp securityTokenRef = re `<wsse:SecurityTokenReference wsu:Id=".*"`;

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
    string:RegExp encryptedData = re `<xenc:EncryptedData xmlns:xenc=".*>`;
    string:RegExp encMethod = re `<xenc:EncryptionMethod Algorithm=".*"/>`;
    string:RegExp keyInfo = re `<ds:KeyInfo xmlns:ds=".*">`;
    string:RegExp secTokenRef = re `<wsse:SecurityTokenReference xmlns:wsse=".*">.*</wsse:SecurityTokenReference>`;
    string:RegExp cipherData = re `<xenc:CipherData>.*</xenc:CipherData>`;
    string:RegExp cipherValue = re `<xenc:CipherValue>.*</xenc:CipherValue>`;

    test:assertTrue(buildToken.includesMatch(encryptedData));
    test:assertTrue(buildToken.includesMatch(encMethod));
    test:assertTrue(buildToken.includesMatch(keyInfo));
    test:assertTrue(buildToken.includesMatch(secTokenRef));
    test:assertTrue(buildToken.includesMatch(cipherData));
    test:assertTrue(buildToken.includesMatch(cipherValue));
}