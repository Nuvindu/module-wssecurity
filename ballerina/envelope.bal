import ballerina/io;
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

public class Envelope {
    private Document document;
    private WSSecurityHeader wsSecHeader;
    private UsernameToken? usernameToken = ();
    private TimestampToken? timestampToken = ();
    private Signature sign;
    private AuthType policy = NONE;
    private Encryption encryption;
    WSSPolicy[] policies = [];

    public function init(string xmlPayload) returns Error? {
        self.document = check new (xmlPayload);
        self.wsSecHeader = check new (self.document);
        self.sign = check new();
        self.encryption = check new();
    }

    public function setUTSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        UsernameToken? ut = self.usernameToken;
        if ut !is () {
            ut.setSignatureAlgorithm(signatureAlgorithm);
        }
    }

    public function setUTEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        UsernameToken? ut = self.usernameToken;
        if ut !is () {
            ut.setEncryptionAlgorithm(encryptionAlgorithm);
    }
    }

    // public function setKey(string publicKey) {
    //     UserData? utData = self.userData;
    //     if utData !is () {
    //         utData.publicKeyPath = publicKey;
    //     }
    // }

    // public function setPrivateKey(string privateKey) {
    //     UserData? utData = self.userData;
    //     if utData !is () {
    //         utData.privateKeyPath = privateKey;
    //     }
    // }

    public function addSecurityHeader() returns Error? {
        return self.wsSecHeader.insertSecHeader();
    }

    public function addTimestampToken(int timeToLive) {
        // self.insertWSSPolicyToArray(TIMESTAMP_TOKEN);
        self.timestampToken = new (self.wsSecHeader, timeToLive);
    }

    public function addUTSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        UsernameToken? ut = self.usernameToken;
        if ut !is () {
            ut.setSignatureAlgorithm(signatureAlgorithm);
        }
    }

    public function addUTEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        UsernameToken? ut = self.usernameToken;
        if ut !is () {
            ut.setEncryptionAlgorithm(encryptionAlgorithm);
        }
    }

    public function insertWSSPolicyToArray(WSSPolicy wssPolicy) {
        int? index = self.policies.indexOf(wssPolicy);
        if index !is () {
            _ = self.policies.remove(index);
        }
        self.policies.push(wssPolicy);
    }

    public function addSignature(string signatureAlgorithm, byte[] signature) returns Error? {
        // UserData? utData = self.userData;
        // if utData !is () {
        //     if utData.authType == ENCRYPT {
        //         utData.authType = SIGN_AND_ENCRYPT;
        //     } else {
        //         utData.authType = SIGNATURE;
        //     }
        //     self.userData = utData;
        // }
        self.sign.setSignatureAlgorithm(signatureAlgorithm);
        self.sign.setSignatureValue(signature);
    }

    public function addEncryption(string encryptionAlgorithm, byte[] encryption) {
        // UserData? utData = self.userData;
        // if utData !is () {
        //     if utData.authType == SIGNATURE {
        //         utData.authType = SIGN_AND_ENCRYPT;
        //     }
        //     self.userData = utData;
        // }
        self.encryption.setEncryptionAlgorithm(encryptionAlgorithm);
        self.encryption.setEncryptedData(encryption);
    }

    public function addUsernameToken(string username, string password, 
                                     PasswordType passwordType, AuthType authType = NONE) {
        self.insertWSSPolicyToArray(USERNAME_TOKEN);
        self.usernameToken = new (self.wsSecHeader, username, password, passwordType);
        self.setPolicy(authType);
        // self.userData = {username: username, password: password, pwType: passwordType, authType: authType};
    }

    public function addX509Token(string|X509Token x509certToken) returns Error? {
        UsernameToken? ut = self.usernameToken;
        X509Token x509Token;
        if x509certToken is string {
            x509Token = check new(x509certToken);
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

    public function addSymmetricBinding(string alias, string password, string symmetricKeyPath) returns Error? {
        _ = self.addUsernameToken(alias, password, TEXT);
        // self.setKey(symmetricKeyPath);
        self.insertWSSPolicyToArray(SYMMETRIC_BINDING);
    }

    public function removeWSSecurityPolicy(WSSPolicy wssPolicy) returns Error? {
        int? index = self.policies.indexOf(wssPolicy);
        if index is () {
            return error("The WSS Policy have not been applied yet.");
        }
        _ = self.policies.remove(index);
    }

    public function addAsymmetricBinding(string alias, string password, string privateKeyPath, 
                                         string publicKeyPath) returns Error? {
        _ = self.addUsernameToken(alias, password, DIGEST);
        // self.setKey(publicKeyPath);
        // self.setPrivateKey(privateKeyPath);
        self.insertWSSPolicyToArray(ASYMMETRIC_BINDING);
    }

    public function setPolicy(AuthType policy) {
        self.policy = policy;
    }

    public function getPolicy() returns AuthType {
        return self.policy;
    }

    // public function setEncryptedData(byte[] encdata) {
    //     UserData? utData = self.userData;
    //     if utData !is () {
    //         utData.encData = encdata;
    //     }
    //     self.userData = utData;
    // }
    // public function addTransportBinding(string username, string password, string passwordType, 
    //                                     boolean addTimestamp = false, int timeToLive = 300) returns Error? {
    //     _ = self.addUsernameToken(username, password, passwordType);
    //     if addTimestamp {
    //         _ = self.addTimestampToken(timeToLive);
    //     }
    //     self.isTransportBinding = true;
    // }

    public function insertSecurityPolicyHeaders(UsernameToken token, WSSPolicy wssPolicy) returns string|Error {
        io:println(self.getPolicy());
        return check token.populateHeaderData(token.getUsername(), token.getPassword(), token.getPasswordType(), 
                                              self.encryption.getEncryptedData(), self.sign.getSignatureValue(), self.getPolicy());
    }
    public function getEncData() returns byte[]? {
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
        UsernameToken? ut = self.usernameToken;
        // UserData? utData = self.userData;
        TimestampToken? tsT = self.timestampToken;
        if tsT is TimestampToken {
            return tsT.addTimestamp();
        }    
        if ut is UsernameToken {
            return self.insertSecurityPolicyHeaders(ut, self.policies[self.policies.length()-1]);
        }
        return error("WS Security Policy headers are not set.");
    }
}
