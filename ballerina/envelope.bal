// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
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

import ballerina/crypto;

public class Envelope {
    private Document document;
    private WSSecurityHeader wsSecHeader;
    private UsernameToken? usernameToken = ();
    private TimestampToken? timestampToken = ();
    private Signature sign;
    private AuthType policy = NONE;
    private Encryption encryption;

    public function init(string xmlPayload) returns Error? {
        self.document = check new (xmlPayload);
        self.wsSecHeader = check new (self.document);
        self.sign = check new ();
        self.encryption = check new ();
    }

    public function addSecurityHeader() returns Error? {
        return self.wsSecHeader.insertSecHeader();
    }

    public function getEnvelopeBody() returns string|Error {
        return self.document.getEnvelopeBody();
    }

    public function addTimestampToken(int timeToLive) returns Error? {
        if timeToLive <= 0 {
            return error Error("Invalid value for `timeToLive`");
        }
        self.timestampToken = new (self.wsSecHeader, timeToLive);
    }

    public function decryptData(byte[] cipherText, EncryptionAlgorithm encryptionAlgorithm,
                                crypto:PrivateKey|crypto:PublicKey? key = ()) returns byte[]|Error {
        return self.encryption.decryptData(cipherText, encryptionAlgorithm, key);
    }

    public function addSignature(string signatureAlgorithm, byte[] signature) {
        self.sign.setSignatureAlgorithm(signatureAlgorithm);
        self.sign.setSignatureValue(signature);
    }

    public function addEncryption(string encryptionAlgorithm, byte[] encryption) {
        self.encryption.setEncryptionAlgorithm(encryptionAlgorithm);
        self.encryption.setEncryptedData(encryption);
    }

    public function addUsernameToken(string username, string password,
                                     PasswordType passwordType, AuthType authType = NONE) {
        self.usernameToken = new (self.wsSecHeader, username, password, passwordType);
        self.setAuthType(authType);
    }

    public function addX509Token(string|X509Token x509certToken) returns Error? {
        UsernameToken? ut = self.usernameToken;
        X509Token x509Token;
        if x509certToken is string {
            x509Token = check new (x509certToken);
        } else {
            x509Token = x509certToken;
        }
        if ut !is () {
            x509Token.addX509Token(ut);
        } else {
            return error("Username Token does not exist.",
                        error("Currently, X509 token is depended on the username token"));
        }
    }

    public function setAuthType(AuthType policy) {
        self.policy = policy;
    }

    public function getAuthType() returns AuthType {
        return self.policy;
    }

    public function getEncryptedData() returns byte[]? {
        UsernameToken? ut = self.usernameToken;
        if ut is UsernameToken {
            return ut.getEncryptedData();
        }
        return;
    }

    public function getSignatureData() returns byte[]? {
        UsernameToken? ut = self.usernameToken;
        if ut is UsernameToken {
            return ut.getSignatureData();
        }
        return;
    }

    public function generateEnvelope() returns string|Error {
        UsernameToken? uToken = self.usernameToken;
        TimestampToken? tsToken = self.timestampToken;
        if tsToken is TimestampToken {
            return tsToken.addTimestamp();
        }
        if uToken is UsernameToken {
            return check uToken.populateHeaderData(uToken.getUsername(), uToken.getPassword(), uToken.getPasswordType(),
                                                   self.encryption, self.sign, self.getAuthType());
        }
        return error("WS Security policy headers are not set.");
    }

    public function applyTimestampToken(*TSRecord tsRecord) returns string|Error {
        check self.addSecurityHeader();
        check self.addTimestampToken(tsRecord.timeToLive);
        return check self.generateEnvelope();
    }

    public function applyUsernameToken(string alias, string password, PasswordType passwordType,
                                       AuthType authType = NONE) returns string|Error {
        check self.addSecurityHeader();
        self.addUsernameToken(alias, password, passwordType, authType);
        return self.generateEnvelope();
    }

    public function applyX509Token(string alias, string password, PasswordType passwordType,
                                   string|X509Token x509certToken) returns string|Error {
        self.addUsernameToken(alias, password, passwordType, SIGNATURE);
        check self.addX509Token(x509certToken);
        return self.generateEnvelope();
    }

    public function applyUTSignature(string alias, string password, PasswordType passwordType,
                                     SignatureAlgorithm signatureAlgorithm, crypto:PrivateKey key,
                                     X509Token? x509Token = ()) returns string|Error {
        byte[] signedData = check self.sign.signData(check self.getEnvelopeBody(), signatureAlgorithm, key);
        self.addSignature(signatureAlgorithm, signedData);
        self.addUsernameToken(alias, password, passwordType, SIGNATURE);
        if x509Token !is () {
            check self.addX509Token(x509Token);
        }
        return self.generateEnvelope();
    }

    public function applyUTEncryption(string alias, string password, EncryptionAlgorithm encryptionAlgorithm,
                                      crypto:PublicKey|crypto:PrivateKey? key = (), X509Token? x509Token = ())
                                      returns string|Error {
        byte[] encryptData = check self.encryption.encryptData(check self.getEnvelopeBody(), encryptionAlgorithm);
        self.addEncryption(encryptionAlgorithm, encryptData);
        self.addUsernameToken(alias, password, DIGEST, ENCRYPT);
        if x509Token !is () {
            check self.addX509Token(x509Token);
        }
        return self.generateEnvelope();
    }

    public function applyAsymmetricBinding(string alias, string password, crypto:PrivateKey privateKey,
                                           crypto:PublicKey publicKey, EncryptionAlgorithm encAlgo,
                                           SignatureAlgorithm signAlgo, X509Token? x509Token = ())
                                           returns string|Error {
        byte[] encryptData = check self.encryption.encryptData(check self.getEnvelopeBody(), encAlgo, publicKey);
        self.addEncryption(encAlgo, encryptData);
        byte[] signedData = check self.sign.signData(check self.getEnvelopeBody(), signAlgo, privateKey);
        self.addSignature(signAlgo, signedData);
        self.addUsernameToken(alias, password, DIGEST, SIGN_AND_ENCRYPT);
        if x509Token !is () {
            check self.addX509Token(x509Token);
        }
        return self.generateEnvelope();
    }

    public function applySymmetricBinding(string alias, string password, crypto:PrivateKey key,
                                          EncryptionAlgorithm encAlgo, SignatureAlgorithm signAlgo,
                                          X509Token? x509Token = ()) returns string|Error {
        byte[] encryptData = check self.encryption.encryptData(check self.getEnvelopeBody(), encAlgo, key);
        self.addEncryption(encAlgo, encryptData);
        byte[] signedData = check self.sign.signData(check self.getEnvelopeBody(), signAlgo, key);
        self.addSignature(signAlgo, signedData);
        self.addUsernameToken(alias, password, DIGEST, SIGN_AND_ENCRYPT);
        if x509Token !is () {
            check self.addX509Token(x509Token);
        }
        return self.generateEnvelope();
    }
}
