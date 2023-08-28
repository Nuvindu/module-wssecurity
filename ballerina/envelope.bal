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
    private UsernameData? userData = ();
    private X509Token? x509Token = ();
    boolean isSymmetricBinding = false;
    boolean isAsymmetricBinding = false;
    boolean isTransportBinding = false;
    private string publicKey = "";
    private string privateKey = "";
    private string signatureAlgorithm = RSA;
    private string encryptionAlgorithm = AES_128_GCM;

    public function init(string xmlPayload) returns error? {
        self.document = check new (xmlPayload);
        self.wsSecHeader = check new (self.document);
    }

    public function setSignatureAlgorithm(string signatureAlgorithm) {
        self.signatureAlgorithm = signatureAlgorithm;
    }

    public function getSignatureAlgorithm() returns string {
        return self.signatureAlgorithm;
    }

    public function setEncryptionAlgorithm(string encryptionAlgorithm) {
        self.encryptionAlgorithm = encryptionAlgorithm;
    }

    public function getEncryptionAlgorithm() returns string {
        return self.encryptionAlgorithm;
    }

    public function setKey(string publicKey) {
        UsernameData? utData = self.userData;
        if utData !is () {
            utData.publicKeyPath = publicKey;
        }
        self.publicKey = publicKey;
    }

    public function getKey() returns string {
        return self.publicKey;
    }

    public function setPrivateKey(string privateKey) {
        UsernameData? utData = self.userData;
        if utData !is () {
            utData.privateKeyPath = privateKey;
        }
        self.privateKey = privateKey;
    }

    public function getPrivateKey() returns string {
        return self.privateKey;
    }

    public function addSecurityHeader() returns error? {
        return self.wsSecHeader.insertSecHeader();
    }

    public function addTimestampToken(int timeToLive) {
        self.timestampToken = new (self.wsSecHeader, timeToLive);
    }

    public function addUsernameToken(string username, string password, string passwordType, string authType = NONE) {
        self.usernameToken = new (self.wsSecHeader, self.signatureAlgorithm, self.encryptionAlgorithm);
        self.userData = {username: username, password: password, pwType: passwordType, authType: authType};
    }

    public function addX509Token(string certificatePath) returns error? {
        self.x509Token = check new("/Users/nuvindu/Ballerina/crypto/src/main/resources/certificate.crt");
        if self.usernameToken !is () {
            (<X509Token>self.x509Token).addX509Token(<UsernameToken>self.usernameToken);
        } else {
            return error("Username Token does not exist.");
        }
    }

    public function addSymmetricBinding(string alias, string password, string symmetricKey) returns error? {
        _ = self.addUsernameToken(alias, password, SIGN_AND_ENCRYPT);
        self.setKey(symmetricKey);
        self.isSymmetricBinding = true;
    }

    public function addAsymmetricBinding(string alias, string password, string privateKeyPath, 
                                         string publicKeyPath) returns error? {
        _ = self.addUsernameToken(alias, password, SIGN_AND_ENCRYPT);
        self.setKey(publicKeyPath);
        self.setPrivateKey(privateKeyPath);
        self.isAsymmetricBinding = true;
    }

    public function addTransportBinding(string username, string password, string passwordType, 
                                        boolean addTimestamp = false, int timeToLive = 300) returns error? {
        _ = self.addUsernameToken(username, password, passwordType);
        if addTimestamp {
            _ = self.addTimestampToken(timeToLive);
        }
        self.isTransportBinding = true;
    }

    public function generateEnvelope() returns string|error {
        string output = "";
        UsernameToken? ut = self.usernameToken;
        UsernameData? utData = self.userData;
        TimestampToken? tsT = self.timestampToken;

        if self.isSymmetricBinding {
            if ut !is () && utData != () {
                return check ut.addUsernameToken(utData.username, utData.password, utData.pwType, utData?.privateKeyPath,
                                                                  utData?.publicKeyPath, SYMMETRIC_SIGN_AND_ENCRYPT);
            }
        } else if self.isAsymmetricBinding {
            if ut !is () && utData != () {
                return check ut.addUsernameToken(utData.username, utData.password, utData.pwType, 
                                                                  utData?.privateKeyPath, utData?.publicKeyPath, 
                                                                  ASYMMETRIC_SIGN_AND_ENCRYPT);
            }
        } else if self.isTransportBinding {
            if tsT !is () {
                output = check tsT.addTimestamp();
            }
            if ut !is () && utData != () {
                return check ut.addUsernameToken(utData.username, utData.password, utData.pwType, (), (), utData.authType);
            }

        } else if ut !is () && utData != () {
                return check ut.addUsernameToken(utData.username, utData.password, utData.pwType, (), (), utData.authType);
        }
        if tsT !is () {
            output = check tsT.addTimestamp();
        }
        if output == "" {
            return error("WS Security Policy headers are not set.");
        }        
        return output;
    }
}
