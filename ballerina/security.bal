// // Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
// //
// // WSO2 Inc. licenses this file to you under the Apache License,
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
// import ballerina/crypto;

// public class Security {

//     private string xmlPayload;
//     private Document document;
//     private WSSecurityHeader wsSecHeader;
//     private UsernameToken? usernameToken = ();
//     private X509Token? x509Token = ();
//     private Signature? sign = ();
//     private Encryption? encrypt = ();

//     public function init(string xmlPayload) returns Error? {
//         self.xmlPayload = xmlPayload;
//         self.document = check new (xmlPayload);
//         self.wsSecHeader = check new (self.document);
//     }
//     public function addTimestamp(int timeToLive) returns string|Error {
//         TimestampToken timestampToken = new (self.wsSecHeader, timeToLive);
//         return check timestampToken.addTimestamp();
//     }

//     public function addUsernameToken(string username, string password, string passwordType) {
//         UsernameToken usernameToken = new(self.wsSecHeader, username, password, passwordType);
//         self.usernameToken = usernameToken;
//     }

//     public function addX509Token(string|X509Token x509Cert) returns Error? {
//         if self.usernameToken is () {
//             return error(USERNAME_NOT_SET_ERROR);
//         }
//         if x509Cert is string {
//             self.x509Token = check new(x509Cert);
//         } else {
//             self.x509Token = x509Cert;
//         }
//     }

//     public function addSignature(SignatureAlgorithm signatureAlgorithm, crypto:PrivateKey key) returns Error? {
//         if self.usernameToken is () {
//             return error(USERNAME_NOT_SET_ERROR);
//         }
//         Signature sign = check new();
//         byte[] signature = check sign.signData(self.xmlPayload, signatureAlgorithm, key);
//         sign.setSignatureAlgorithm(signatureAlgorithm);
//         sign.setSignatureValue(signature);
//         self.sign = sign;
//     }

//     public function addEncryption(EncryptionAlgorithm encryptionAlgorithm, crypto:PrivateKey|crypto:PublicKey key) returns Error? {
//         if self.usernameToken is () {
//             return error(USERNAME_NOT_SET_ERROR);
//         }
//         Encryption encrypt = check new();
//         byte[] encryption = check encrypt.encryptData(check self.document.getEnvelopeBody(), encryptionAlgorithm, key);
//         encrypt.setEncryptionAlgorithm(encryptionAlgorithm);
//         encrypt.setEncryptedData(encryption);
//         self.encrypt = encrypt;
//     }

//     public function generateEnvelope() returns string|Error {
//         UsernameToken? usernameToken = self.usernameToken;
//         Signature? signature = self.sign;
//         Encryption? encryption = self.encrypt;
//         if usernameToken is () {
//             return error(USERNAME_NOT_SET_ERROR);
//         }
//         if signature !is () {
//             return check usernameToken
//                 .addUsernameToken(usernameToken.getUsername(), usernameToken.getPassword(), 
//                                      usernameToken.getPasswordType(), signature.getSignatureValue(),
//                                      [], SIGNATURE);
//         // } else if signature !is () {
//         //     return check usernameToken
//         //         .addUTSignature(usernameToken.getUsername(), usernameToken.getPassword(), 
//         //                         usernameToken.getPasswordType(), signature.getSignatureValue());
//         // } else if encryption !is () {
//         //     return check usernameToken
//         //         .addUTEncryption(usernameToken.getUsername(), usernameToken.getPassword(), 
//         //                          usernameToken.getPasswordType(),  encryption.getEncryptedData());
//         // } else {
//         //     return check usernameToken
//         //         .addUT(usernameToken.getUsername(), usernameToken.getPassword(), usernameToken.getPasswordType());
//         // }
        
//         }
//         return error("qqq");
//     }

//     public function applyAsymmetricBinding(crypto:PublicKey serverPublicKey, crypto:PrivateKey clientPrivateKey, 
//                                            SignatureAlgorithm signAlgorithm, EncryptionAlgorithm encAlgorithm) 
//                                            returns Error? {
//         UsernameToken? usernameToken = self.usernameToken;
//         if usernameToken is () {
//             return error(USERNAME_NOT_SET_ERROR);
//         }
//         Error? signature = self.addSignature(signAlgorithm, clientPrivateKey);
//         if signature is Error {
//             return signature;
//         }
//         return self.addEncryption(encAlgorithm, serverPublicKey);
//     }

//     public function applySymmetricBinding(crypto:PrivateKey symmetricKey, 
//                                           SignatureAlgorithm signAlgorithm, EncryptionAlgorithm encAlgorithm) 
//                                           returns Error? {
//         UsernameToken? usernameToken = self.usernameToken;
//         if usernameToken is () {
//             return error(USERNAME_NOT_SET_ERROR);
//         }
//         Error? signature = self.addSignature(signAlgorithm, symmetricKey);
//         if signature is Error {
//             return signature;
//         }
//         return self.addEncryption(encAlgorithm, symmetricKey);
//     }
// }
 