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

// import ballerina/io;
import ballerina/test;

@test:Config {
    groups: ["timestamp_token"]
}
function testTimestampToken() returns error? {
    string xmlPayload = string `<?xml version="1.0" encoding="UTF-8" standalone="no"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"> <soap:Header></soap:Header> <soap:Body> <yourPayload>...</yourPayload> </soap:Body> </soap:Envelope>`;
    
    Document doc = check new(xmlPayload);
    WSSecurityHeader ws = check new(doc);
    error? insertSecHeader = ws.insertSecHeader();
    test:assertTrue(insertSecHeader is ());
    Request request = new();
    error? securityHeader = request.setSecurityHeader(ws);
    test:assertTrue(securityHeader is ());
    TimestampToken timestamp = new();
    string timestampResult = check timestamp.setTimestamp(ws);
    // io:println(timestampResult);
    string:RegExp ts_token = re `<wsu:Timestamp wsu:Id=".*">`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;
    string:RegExp expires = re `<wsu:Expires>.*</wsu:Expires>`;
    test:assertTrue(timestampResult.includesMatch(ts_token));
    test:assertTrue(timestampResult.includesMatch(created));
    test:assertTrue(timestampResult.includesMatch(expires));
}
