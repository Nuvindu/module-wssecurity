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
    private string username;
    private string password;
    private string passwordType;

    public function init(WSSecurityHeader wsSecHeader, string username, string password, string passwordType) {
        self.'type = USERNAME_TOKEN;
        self.username = username;
        self.password = password;
        self.passwordType = passwordType;
        self.nativeUT = newToken(wsSecHeader, self.signatureAlgorithm, self.encryptionAlgorithm);
    }


    public function setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        self.signatureAlgorithm = signatureAlgorithm;
    }

    public function getUsername() returns string {
        return self.username;
    }

    public function getPassword() returns string {
        return self.password;
    }

    public function getPasswordType() returns string {
        return self.passwordType;
    }

    public function setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        self.encryptionAlgorithm = encryptionAlgorithm;
    }

    public function getEncryptionAlgorithm() returns EncryptionAlgorithm {
        return self.encryptionAlgorithm;
    }
    public function populateHeaderData(string username, string password, string pwType,
                                     byte[] encData, byte[] signValue, AuthType authType = NONE)
                                     returns string|Error = @java:Method {
        'class: "org.wssecurity.UsernameToken"
    } external;

    // public function addUTSignAndEncrypt(string username, string password, string pwType,
    //                                     byte[] encData, byte[] signValue, AuthType authType = NONE)
    //                                     returns string|Error = @java:Method {
    //     'class: "org.wssecurity.UsernameToken"
    // } external;

    // public function addUTSignature(string username, string password, string pwType,
    //                                byte[] signValue, AuthType authType = NONE)
    //                                returns string|Error = @java:Method {
    //     'class: "org.wssecurity.UsernameToken"
    // } external;

    // public function addUTEncryption(string username, string password, string pwType,
    //                                 byte[] encData, AuthType authType = NONE)
    //                                 returns string|Error = @java:Method {
    //     'class: "org.wssecurity.UsernameToken"
    // } external;

    // public function addUT(string username, string password, string pwType) returns string|Error = @java:Method {
    //     'class: "org.wssecurity.UsernameToken"
    // } external;

    public function getEncryptedData() returns byte[] = @java:Method {
        'class: "org.wssecurity.UsernameToken"
    } external;

    public function getSignatureData() returns byte[] = @java:Method {
        'class: "org.wssecurity.UsernameToken"
    } external;
}

function newToken(WSSecurityHeader wsSecHeader, string signatureAlgorithm, string encryptionAlgorithm) 
    returns handle = @java:Constructor {
    'class: "org.wssecurity.UsernameToken"
} external;
