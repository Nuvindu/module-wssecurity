// // Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
// //
// // WSO2 LLC. licenses this file to you under the Apache License,
// // Version 2.0 (the "License"); you may not use this file except
// // in compliance with the License.
// // You may obtain a copy of the License at
// //
// // http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing,
// // software distributed under the License is distributed on an
// // "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// // KIND, either express or implied.  See the License for the
// // specific language governing permissions and limitations
// // under the License.

// import ballerina/test;
// import ballerina/crypto;
// import ballerina/io;

// @test:Config {
//     groups: ["username_token", "signature", "qwerty"]
// }
// function testSignature() returns error? {
//     string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

//     crypto:KeyStore keyStore = {
//         path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
//         password: "security"
//     };
//     crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");
    
//     Security security = check new(xmlPayload);
//     security.addUsernameToken(USERNAME, PASSWORD, TEXT);
//     Error? signature = security.addSignature(RSA_SHA256, privateKey);
//     string generateEnvelope = check security.generateEnvelope();
//     io:println(generateEnvelope);
//     // Envelope env = check new(xmlPayload);
//     // Error? securityHeader = env.addSecurityHeader();
//     // test:assertEquals(securityHeader, ());

//     // // env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGN_AND_ENCRYPT);
//     // crypto:KeyStore keyStore = {
//     //     path: "/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/keys/wss40.p12",
//     //     password: "security"
//     // };
//     // crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "wss40", "security");

//     // crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "wss40");
    
//     // Signature sign = check new();
//     // byte[] signData = check sign.signData(bodyValue, RSA_SHA256, symmetricKey);

//     // Error? signature = env.addSignature(RSA_SHA256, signData);

//     // env.addUsernameToken(USERNAME, PASSWORD, DIGEST, SIGNATURE);
//     // Error? x509Token = env.addX509Token(X509_PUBLIC_CERT_PATH);
//     // string buildToken = check env.generateEnvelope();
//     // // io:println(buildToken);
//     // byte[] signedData = <byte[]>env.getSignatureData();

//     // boolean validity = check crypto:verifyRsaSha256Signature(bodyValue.toBytes(), signedData, publicKey);
//     // test:assertTrue(validity);

//     // test:assertEquals(signature, ());

//     // assertSignatureWithX509(buildToken);
//     // assertEncryptedPart(buildToken);
// }

// // @test:Config {
// //     groups: ["timestamp_token", "env"]
// // }
// // function testX509Signature() returns error? {
// //     string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    
// //     Envelope env = check new(xmlPayload);
// //     Error? securityHeader = env.addSecurityHeader();
// //     test:assertEquals(securityHeader, ());

// //     env.addTimestampToken(600);
// //     string generateEnvelope = check env.generateEnvelope();
// //     // io:println(generateEnvelope);
// //     string:RegExp ts_token = re `<wsu:Timestamp wsu:Id=".*">`;
// //     string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;
// //     string:RegExp expires = re `<wsu:Expires>.*</wsu:Expires>`;
// //     test:assertTrue(generateEnvelope.includesMatch(ts_token));
// //     test:assertTrue(generateEnvelope.includesMatch(created));
// //     test:assertTrue(generateEnvelope.includesMatch(expires));
// // }