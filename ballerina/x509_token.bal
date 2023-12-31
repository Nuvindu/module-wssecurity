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

class X509Token {
    *Token;
    private handle nativeX509Token;

    public function init(string filePath) returns Error? {
        self.'type = X509_TOKEN;
        self.nativeX509Token = check newX509Token(filePath);
    }

    function addX509Token(UsernameToken usernameToken) = @java:Method {
        'class: "org.wssec.X509SecToken"
    } external;
}

function newX509Token(string filePath) returns handle|Error = @java:Constructor {
    'class: "org.wssec.X509SecToken"
} external;
