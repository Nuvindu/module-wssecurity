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

    public function init(string xmlPayload) returns error? {
        self.document = check new (xmlPayload);
        self.wsSecHeader = check new (self.document);
    }

    public function setKey(string publicKey) {
        self.publicKey = publicKey;
    }

    public function getKey() returns string {
        return self.publicKey;
    }

    public function setPrivateKey(string privateKey) {
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
        self.usernameToken = new (self.wsSecHeader);
        self.userData = {username: username, password: password, pwType: passwordType, authType: authType};
    }

    public function addX509Token(string certificatePath) returns error? {
        self.x509Token = new(certificatePath);
        if self.usernameToken !is () {
            (<X509Token>self.x509Token).addX509Token(<UsernameToken>self.usernameToken);
        }
    }

    public function addSymmetricBinding(string alias, string password, string publicKey, string? certPath = ()) returns error? {
        self.setKey("/Users/nuvindu/Ballerina/soap/module-wssecurity/native/src/main/resources/wss40_1.pem");
        _ = self.addUsernameToken(alias, password, SIGN_AND_ENCRYPT);
        if certPath !is () {
            _ = check self.addX509Token(certPath);
        }
        self.isSymmetricBinding = true;
    }

    public function addAsymmetricBinding(string alias, string password, string privateKey, 
                                         string publicKey, string? certPath = ()) returns error? {
        self.setKey(publicKey);
        self.setPrivateKey(privateKey);
        _ = self.addUsernameToken(alias, password, SIGN_AND_ENCRYPT);
        if certPath !is () {
            _ = check self.addX509Token(certPath);
        }
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
        if self.isSymmetricBinding {
            return check (<UsernameToken>self.usernameToken)
                    .addUsernameTokenWithKey((<UsernameData>self.userData).username, 
                                             (<UsernameData>self.userData).password, 
                                             (<UsernameData>self.userData).pwType, 
                                             self.getKey(), SYMMETRIC_SIGN_AND_ENCRYPT);
        }
        if self.isAsymmetricBinding {
            return check (<UsernameToken>self.usernameToken)
                    .addUsernameTokenWithAsymmetricKey((<UsernameData>self.userData).username, 
                                                       (<UsernameData>self.userData).password, 
                                                       (<UsernameData>self.userData).pwType, self.getPrivateKey(),
                                                       self.getKey(), ASYMMETRIC_SIGN_AND_ENCRYPT);
        }
        if self.isTransportBinding {
            if self.timestampToken !is () {
                output = check (<TimestampToken>self.timestampToken).addTimestamp();
            }
            output = check (<UsernameToken>self.usernameToken)
                        .addUsernameToken((<UsernameData>self.userData).username, (<UsernameData>self.userData).password,
                                      (<UsernameData>self.userData).pwType, (<UsernameData>self.userData).authType); 

        }
        if self.timestampToken !is () {
            output = check (<TimestampToken>self.timestampToken).addTimestamp();
        }
        if self.usernameToken !is () {
            //TODO: possibility of spread operator
            output = check (<UsernameToken>self.usernameToken)
                        .addUsernameToken((<UsernameData>self.userData).username, (<UsernameData>self.userData).password,
                                      (<UsernameData>self.userData).pwType, (<UsernameData>self.userData).authType);            
        }
        return output;
    }
}
