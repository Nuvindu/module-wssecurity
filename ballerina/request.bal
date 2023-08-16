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

public class Request {
    private handle nativeRequest;

    public function init() {
        self.nativeRequest = newRequest();
    }

    public function setUsername(string username) = @java:Method {
        'class: "org.wssecurity.Request"
    } external;

    public function getUsername() returns string = @java:Method {
        'class: "org.wssecurity.Request"
    } external;

    public function setPasswordType(string passwordType) = @java:Method {
        'class: "org.wssecurity.Request"
    } external;

    public function setSecurityHeader(WSSecurityHeader wsSecurityHeader) returns error? = @java:Method {
        'class: "org.wssecurity.Request"
    } external;
}

function newRequest() returns handle = @java:Constructor {
    'class: "org.wssecurity.Request"
} external;
