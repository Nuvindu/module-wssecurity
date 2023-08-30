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
import ballerina/jballerina.java;

public class UsernameToken {
    *Token;

    private handle nativeUT;
    private SignatureAlgorithm signatureAlgorithm = HMAC_SHA1;
    private EncryptionAlgorithm encryptionAlgorithm = AES_128_GCM;

    public function init(WSSecurityHeader wsSecHeader, SignatureAlgorithm? signatureAlgorithm = (), 
                         EncryptionAlgorithm? encryptionAlgorithm = ()) {
        self.'type = USERNAME_TOKEN;
        if signatureAlgorithm !is () {
            self.signatureAlgorithm = signatureAlgorithm;
        }
        if encryptionAlgorithm !is () {
            self.encryptionAlgorithm = encryptionAlgorithm;
        }
        self.nativeUT = newToken(wsSecHeader, self.signatureAlgorithm, self.encryptionAlgorithm);
    }

    public function setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        self.signatureAlgorithm = signatureAlgorithm;
    }

    public function getSignatureAlgorithm() returns SignatureAlgorithm {
        return self.signatureAlgorithm;
    }

    public function setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        self.encryptionAlgorithm = encryptionAlgorithm;
    }

    public function getEncryptionAlgorithm() returns EncryptionAlgorithm {
        return self.encryptionAlgorithm;
    }
    public function addUsernameToken(string username, string password, string pwType,
                                     string? privateKey, string? publicKey, AuthType authType = NONE)
                                     returns string|Error = @java:Method {
        'class: "org.wssecurity.UsernameToken"
    } external;
}

function newToken(WSSecurityHeader wsSecHeader, string signatureAlgorithm, string encryptionAlgorithm) 
    returns handle = @java:Constructor {
    'class: "org.wssecurity.UsernameToken"
} external;
