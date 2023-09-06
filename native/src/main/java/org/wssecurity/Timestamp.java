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

package org.wssecurity;

import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import org.apache.wss4j.dom.message.WSSecTimestamp;

import static org.wssecurity.Constants.NATIVE_SEC_HEADER;
import static org.wssecurity.Constants.NATIVE_TS_TOKEN;

public class Timestamp {

    private final WSSecTimestamp timestamp;

    public Timestamp(BObject secHeader, int timeToLive) {
        BHandle handle = (BHandle) secHeader.get(StringUtils.fromString(NATIVE_SEC_HEADER));
        WSSecurityHeader wsSecurityHeader = (WSSecurityHeader) handle.getValue();
        timestamp = new WSSecTimestamp(wsSecurityHeader.getWsSecHeader());
        timestamp.setTimeToLive(timeToLive);
    }

    protected WSSecTimestamp getTimestamp() {
        return timestamp;
    }

    public static Object addTimestamp(BObject timestamp) {
        BHandle handle = (BHandle) timestamp.get(StringUtils.fromString(NATIVE_TS_TOKEN));
        Timestamp timestampObj = (Timestamp) handle.getValue();
        WSSecTimestamp timestampBuilder = timestampObj.getTimestamp();
        try {
            return StringUtils.fromString(DocumentBuilder.convertDocumentToString(timestampBuilder.build()));
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }
}
