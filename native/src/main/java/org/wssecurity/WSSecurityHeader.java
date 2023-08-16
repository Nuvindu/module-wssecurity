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

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.message.WSSecHeader;

public class WSSecurityHeader {
    private final WSSecHeader wsSecHeader;

    public WSSecurityHeader(BObject documentBuilder) {
        BHandle handle = (BHandle) documentBuilder.get(StringUtils.fromString("nativeDoc"));
        DocBuilder docBuilder = (DocBuilder) handle.getValue();
        this.wsSecHeader = new WSSecHeader(docBuilder.getNativeDocument());
    }

    protected WSSecHeader getWsSecHeader() {
        return wsSecHeader;
    }

    public static void insertSecHeader(BObject secHeader) throws WSSecurityException {
        BHandle handle = (BHandle) secHeader.get(StringUtils.fromString("nativeSecHeader"));
        WSSecurityHeader wsSecurityHeader = (WSSecurityHeader) handle.getValue();
        wsSecurityHeader.getWsSecHeader().insertSecurityHeader();
    }
}
