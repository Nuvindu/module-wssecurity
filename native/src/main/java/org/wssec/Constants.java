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

package org.wssec;

public class Constants {

    public static final int ITERATION = 1000;
    public static final String NONE = "NONE";
    public static final String DIGEST = "DIGEST";
    public static final String SIGNATURE = "SIGNATURE";
    public static final String ENCRYPT = "ENCRYPT";
    public static final String SIGN_AND_ENCRYPT = "SIGN_AND_ENCRYPT";
    public static final String TIMESTAMP_TOKEN = "TIMESTAMP_TOKEN";
    public static final String USERNAME_TOKEN = "USERNAME_TOKEN";
    public static final String SYMMETRIC_BINDING = "SYMMETRIC_BINDING";
    public static final String ASYMMETRIC_BINDING = "ASYMMETRIC_BINDING";
    public static final String DERIVED_KEY_TEXT = "DERIVED_KEY_TEXT";
    public static final String DERIVED_KEY_DIGEST = "DERIVED_KEY_DIGEST";
    public static final String NATIVE_SEC_HEADER = "nativeSecHeader";
    public static final String NATIVE_X509_TOKEN = "nativeX509Token";
    public static final String NATIVE_TS_TOKEN = "nativeTimestampToken";
    public static final String NATIVE_UT = "nativeUT";
    public static final String NATIVE_DOCUMENT = "nativeDocumentBuilder";
    public static final String NATIVE_SIGNATURE = "nativeSignature";
    public static final String NATIVE_ENCRYPTION = "nativeEncryption";
    public static final String SOAP_BODY_TAG = "soap:Body";
    public static final String SIGNATURE_VALUE_TAG = "ds:SignatureValue";
    public static final String SIGNATURE_METHOD_TAG = "ds:SignatureMethod";
    public static final String ENCRYPTION_METHOD_TAG = "xenc:EncryptionMethod";
    public static final String NAMESPACE_URI_ENC = "http://www.w3.org/2001/04/xmlenc#";
    public static final String CIPHER_VALUE_TAG = "CipherValue";
    public static final String X509 = "X.509";
    public static final String EMPTY_XML_DOCUMENT_ERROR = "XML Document is empty";
}
