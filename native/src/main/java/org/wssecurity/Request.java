//// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
////
//// WSO2 Inc. licenses this file to you under the Apache License,
//// Version 2.0 (the "License"); you may not use this file except
//// in compliance with the License.
//// You may obtain a copy of the License at
////
//// http://www.apache.org/licenses/LICENSE-2.0
////
//// Unless required by applicable law or agreed to in writing,
//// software distributed under the License is distributed on an
//// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
//// KIND, either express or implied.  See the License for the
//// specific language governing permissions and limitations
//// under the License.
//package org.wssecurity;
//
//import io.ballerina.runtime.api.utils.StringUtils;
//import io.ballerina.runtime.api.values.BHandle;
//import io.ballerina.runtime.api.values.BObject;
//import io.ballerina.runtime.api.values.BString;
//import org.apache.wss4j.dom.engine.WSSConfig;
//import org.apache.wss4j.dom.handler.RequestData;
//
///**
// * Provide APIs to request data.
// */
//public class Request {
//    private final RequestData requestData;
//    public Request() {
//        requestData = new RequestData();
//        requestData.setWssConfig(WSSConfig.getNewInstance());
//    }
//
//    protected RequestData getRequestDataObj() {
//        return this.requestData;
//    }
//
//    public static void setUsername(BObject request, BString username) {
//        RequestData requestData = getRequestData(request);
//        requestData.setUsername(String.valueOf(username));
//    }
//
//    public static BString getUsername(BObject request) {
//        RequestData requestData = getRequestData(request);
//        return StringUtils.fromString(requestData.getUsername());
//    }
//
//    public static BString getSecHeader(BObject request) {
//        RequestData requestData = getRequestData(request);
//        return StringUtils.fromString(requestData.getUsername());
//    }
//
//    public static void setPasswordType(BObject request, BString passwordType) {
//        RequestData requestData = getRequestData(request);
//        requestData.setPwType(passwordType.getValue());
//    }
//
//    public static void setSecurityHeader(BObject request, BObject securityHeader)  {
//        BHandle handle = (BHandle) securityHeader.get(StringUtils.fromString(Constants.NATIVE_SEC_HEADER));
//        WSSecurityHeader wsSecurityHeader = (WSSecurityHeader) handle.getValue();
//        RequestData requestData = getRequestData(request);
//        requestData.setSecHeader(wsSecurityHeader.getWsSecHeader());
//    }
//
//    private static RequestData getRequestData(BObject request) {
//        BHandle handle = (BHandle) request.get(StringUtils.fromString(Constants.NATIVE_REQUEST));
//        Request request1 = (Request) handle.getValue();
//        return request1.getRequestDataObj();
//    }
//}
