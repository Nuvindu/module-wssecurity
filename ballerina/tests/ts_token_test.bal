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
    groups: ["timestamp_token"]
}
function testTimestampToken() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;

    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    xml securedEnvelope = check applyTimestampToken(envelope = envelope, timeToLive = 600);
    string envelopeString = (securedEnvelope/<soap:Header>/*).toBalString();
    string:RegExp ts_token = re `<wsu:Timestamp wsu:Id=".*">`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;
    string:RegExp expires = re `<wsu:Expires>.*</wsu:Expires>`;
    test:assertTrue(envelopeString.includesMatch(ts_token));
    test:assertTrue(envelopeString.includesMatch(created));
    test:assertTrue(envelopeString.includesMatch(expires));
}

@test:Config {
    groups: ["timestamp_token", "error"]
}
function testTimestampTokenIncorrectTimeError() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;

    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    TSRecord tsRecord = {
        envelope: envelope,
        timeToLive: -1
    };
    xml|Error generateEnvelope = applyTimestampToken(tsRecord);

    test:assertTrue(generateEnvelope is Error);
    if generateEnvelope is Error {
        test:assertEquals(generateEnvelope.message(), "Invalid value for `timeToLive`");
    }
}
