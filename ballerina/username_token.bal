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
    private handle nativeUT;

    public function init(WSSecurityHeader wsSecHeader) {
        self.nativeUT = newToken(wsSecHeader);
    }

    public function addUsernameToken(string username, string password, 
                                     string pwType, string authType = NONE) returns string|error = @java:Method {
        'class: "org.wssecurity.UsernameToken"
    } external;

    public function addUsernameTokenWithKey(string username, string password, string pwType,
                                                string privateKey, string authType = NONE) returns string|error = @java:Method {
        'class: "org.wssecurity.UsernameToken"
    } external;

        public function addUsernameTokenWithAsymmetricKey(string username, string password, string pwType,
                                                          string privateKey, string publicKey, string authType = NONE)
                                                          returns string|error = @java:Method {
        'class: "org.wssecurity.UsernameToken"
    } external;
}

function newToken(WSSecurityHeader wsSecHeader) returns handle = @java:Constructor {
    'class: "org.wssecurity.UsernameToken"
} external;
