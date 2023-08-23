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

    public function init(string xmlPayload) returns error? {
        self.document = check new (xmlPayload);
        self.wsSecHeader = check new (self.document);
    }

    public function addSecurityHeader() returns error? {
        return self.wsSecHeader.insertSecHeader();
    }

    public function addTimestampToken() returns error? {
        TimestampToken timestamp = new ();
        _ = check timestamp.setTimestamp(self.wsSecHeader);
    }

    public function addUsernameToken(string username, string password, string passwordType) returns error? {
        self.usernameToken = new (self.wsSecHeader);
        self.userData = {username: username, password: password, pwType: passwordType};
    }

    public function addX509Token(string certificatePath) returns error? {
        self.x509Token = new(certificatePath);
        if self.usernameToken !is () {
            (<X509Token>self.x509Token).addX509Token(<UsernameToken>self.usernameToken);
        } else {
            return error("Username token is not defined.");
        }
    }

    public function addSymmetricBinding(string alias, string password, string? certPath = ()) returns error? {
        _ = check self.addUsernameToken(alias, password, SIGN_AND_ENCRYPT);
        if certPath !is () {
            _ = check self.addX509Token(certPath);
        }
        self.isSymmetricBinding = true;
    }

    public function addAsymmetricBinding(string alias, string password, byte[] privateKey, string? certPath = ()) returns error? {
        _ = check self.addUsernameToken(alias, password, SIGN_AND_ENCRYPT);
        if certPath !is () {
            _ = check self.addX509Token(certPath);
        }
        self.isAsymmetricBinding = true;
    }

    public function generateEnvelope() returns string|error? {
        string output = "";
        if self.isSymmetricBinding {
            return check (<UsernameToken>self.usernameToken)
                    .buildToken((<UsernameData>self.userData).username, (<UsernameData>self.userData).password, SIGN_AND_ENCRYPT);
        }
        if self.isAsymmetricBinding {
            return check (<UsernameToken>self.usernameToken)
                    .buildTokenWithKey((<UsernameData>self.userData).username, (<UsernameData>self.userData).password,
                                       ASYMMETRIC_SIGN_AND_ENCRYPT, "key");
        }
        if self.timestampToken !is () {
            output = check (<TimestampToken>self.timestampToken).setTimestamp(self.wsSecHeader);
        }
        if self.usernameToken !is () {
            output = check (<UsernameToken>self.usernameToken)
                    .buildToken((<UsernameData>self.userData).username, (<UsernameData>self.userData).password,
                                (<UsernameData>self.userData).pwType);
        }
        return output;
    }
}
