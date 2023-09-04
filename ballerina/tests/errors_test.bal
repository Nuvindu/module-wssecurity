// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
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

import ballerina/test;

@test:Config {
    groups: ["error"]
}
function testNoPolicyError() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;

    Envelope env = check new(xmlPayload);
    string|Error policyError = env.generateEnvelope();
    error expectedError = error( "WS Security policy headers are not set.");
    test:assertTrue(policyError is Error);
    if policyError is Error {
        test:assertEquals(policyError.message(), expectedError.message());
    }
}

@test:Config {
    groups: ["error", "username_token", "x509"]
}
function testUTDoesNotExistError() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    string x509certPath = "/Users/nuvindu/Ballerina/crypto/src/main/resources/certificate.crt";
    string expectedErrorMessage = "Username Token does not exist.";
    error expectedErrorCause = error("Currently, X509 token is depended on the username token");
    Envelope env = check new(xmlPayload); 
    X509Token|Error x509Token = new(x509certPath);
    test:assertTrue(x509Token !is Error);
    Error? x509TokenResult = env.addX509Token(x509certPath);
    test:assertTrue(x509TokenResult !is ());
    if x509TokenResult is Error {
        test:assertEquals(x509TokenResult.message(), expectedErrorMessage);
        test:assertEquals((<error>x509TokenResult.cause()).message(), expectedErrorCause.message());
    }
}
