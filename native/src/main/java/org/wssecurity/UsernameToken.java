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
import io.ballerina.runtime.api.values.BString;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.w3c.dom.Document;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import static org.apache.wss4j.common.WSS4JConstants.PASSWORD_DIGEST;
import static org.apache.wss4j.common.WSS4JConstants.PASSWORD_TEXT;
import static org.wssecurity.Constants.DERIVED_KEY_DIGEST;
import static org.wssecurity.Constants.DERIVED_KEY_TEXT;
import static org.wssecurity.Constants.DIGEST;
import static org.wssecurity.Constants.EMPTY_XML_DOCUMENT_ERROR;
import static org.wssecurity.Constants.ENCRYPT;
import static org.wssecurity.Constants.NATIVE_ENCRYPTION;
import static org.wssecurity.Constants.NATIVE_SEC_HEADER;
import static org.wssecurity.Constants.NATIVE_SIGNATURE;
import static org.wssecurity.Constants.NATIVE_UT;
import static org.wssecurity.Constants.NONE;
import static org.wssecurity.Constants.SIGNATURE;
import static org.wssecurity.Constants.SIGN_AND_ENCRYPT;

public class UsernameToken {

    private final WSSecUsernameToken usernameToken;

    private String username;
    private String password;
    private String passwordType;
    private final String signAlgo;
    private final String encAlgo;
    private final Document document;
    private X509SecToken x509SecToken = null;

    protected Document getDocument() {
        return document;
    }

    public UsernameToken(BObject wsSecurityHeader, BString signatureAlgo, BString encryptionAlgo) {
        BHandle handle = (BHandle) wsSecurityHeader.get(StringUtils.fromString(NATIVE_SEC_HEADER));
        WSSecurityHeader securityHeader = (WSSecurityHeader) handle.getValue();
        this.usernameToken = new WSSecUsernameToken(securityHeader.getWsSecHeader());
        this.signAlgo = signatureAlgo.getValue();
        this.encAlgo = encryptionAlgo.getValue();
        this.document = securityHeader.getDocument();
    }

    public static void setUsername(BObject userToken, BString username) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        usernameTokenObj.setUsername(username.getValue());
    }

    public static void setPassword(BObject userToken, BString password) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        usernameTokenObj.setPassword(password.getValue());
    }

    public static void setPasswordType(BObject userToken, BString passwordType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        usernameTokenObj.setPasswordType(passwordType.getValue());
    }

    protected String getUsername() {
        return username;
    }

    protected void setUsername(String username) {
        this.username = username;
    }

    protected String getPassword() {
        return password;
    }

    protected void setPassword(String password) {
        this.password = password;
    }

    protected String getPasswordType() {
        return passwordType;
    }

    protected void setPasswordType(String passwordType) {
        this.passwordType = passwordType;
    }

    protected WSSecUsernameToken getUsernameToken() {
        return usernameToken;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public String getEncAlgo() {
        return encAlgo;
    }

    protected void setX509Token(X509SecToken x509SecToken) {
        this.x509SecToken =  x509SecToken;
    }

    public X509SecToken getX509SecToken() {
        return x509SecToken;
    }

    protected Crypto getCryptoProperties() {
        return (x509SecToken == null) ? null : x509SecToken.getCryptoProperties();
    }

    public static BArray getEncryptedData(BObject userToken) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        return ValueCreator.createArrayValue(WSSecurityUtils.getEncryptedData(usernameTokenObj.getDocument()));
            }

    public static BArray getSignatureData(BObject userToken) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        return ValueCreator.createArrayValue(WSSecurityUtils.getSignatureValue(usernameTokenObj.getDocument()));
    }

    public static Object populateHeaderData(BObject userToken, BString username, BString password,
                                            BString pwType, BObject encryptedData, BObject signatureValue,
                                            BString authType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();

        handle = (BHandle) encryptedData.get(StringUtils.fromString(NATIVE_ENCRYPTION));
        Encryption encryption = (Encryption) handle.getValue();

        handle = (BHandle) signatureValue.get(StringUtils.fromString(NATIVE_SIGNATURE));
        Signature signature = (Signature) handle.getValue();

        byte[] salt = UsernameTokenUtil.generateSalt(true);
        Document xmlDocument;
        try {
            switch (authType.getValue()) {
                case NONE -> {
                    setUTChildElements(usernameToken, pwType.getValue(), username.getValue(), password.getValue());
                    switch (pwType.getValue()) {
                        case DERIVED_KEY_TEXT, DERIVED_KEY_DIGEST ->  {
                            usernameToken.addDerivedKey(Constants.ITERATION);
                            xmlDocument = usernameToken.build(UsernameTokenUtil.generateSalt(true));
                        }
                        default -> xmlDocument = usernameToken.build();
                    }
                }
                case SIGNATURE -> {
                    xmlDocument = createSignatureTags(usernameTokenObj, username.getValue(), password.getValue(),
                            pwType.getValue(), salt, pwType.getValue().equals(DERIVED_KEY_TEXT)
                                    || pwType.getValue().equals(DERIVED_KEY_DIGEST));
                    WSSecurityUtils.setSignatureValue(xmlDocument, signature.getSignatureValue());
                }
                case ENCRYPT -> {
                    setUTChildElements(usernameToken, DIGEST, username.getValue(), password.getValue());
                    usernameToken.build();
                    xmlDocument = WSSecurityUtils.encryptEnvelope(usernameToken, usernameTokenObj.getEncAlgo(), salt);
                    WSSecurityUtils.setEncryptedData(xmlDocument, encryption.getEncryptedData());
                }
                case SIGN_AND_ENCRYPT -> {
                    createSignatureTags(usernameTokenObj, username.getValue(), password.getValue(),
                            pwType.getValue(), salt, pwType.getValue().equals(DERIVED_KEY_TEXT)
                                    || pwType.getValue().equals(DERIVED_KEY_DIGEST));
                    xmlDocument = WSSecurityUtils.encryptEnvelope(usernameToken, usernameTokenObj.getEncAlgo(), salt);
                    WSSecurityUtils.setEncryptedData(xmlDocument, encryption.getEncryptedData());
                    WSSecurityUtils.setSignatureValue(xmlDocument, signature.getSignatureValue());
                }
                default -> {
                    return createError("Given ws security policy is currently not supported");
                }
            }
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Document createSignatureTags(UsernameToken usernameTokenObj, String username, String password,
                                               String passwordType, byte[] salt,
                                               boolean useDerivedKey) throws Exception {
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        RequestData reqData = new RequestData();
        reqData.setSecHeader(usernameToken.getSecurityHeader());
        reqData.setWssConfig(WSSConfig.getNewInstance());
        reqData.setWsDocInfo(new WSDocInfo(usernameTokenObj.getDocument()));
        setUTChildElements(usernameToken, passwordType, username, password);
        usernameToken.prepare(salt);
        WSSecurityUtils.buildSignature(reqData,
                    WSSecurityUtils.prepareSignature(reqData, usernameTokenObj,
                                                     usernameTokenObj.getSignAlgo(), useDerivedKey));
        return usernameToken.build(salt);
    }

    public static void setUTChildElements(WSSecUsernameToken usernameToken, String passwordType,
                                  String username, String password) {
        if (Objects.equals(passwordType, DIGEST)
                || Objects.equals(passwordType, DERIVED_KEY_DIGEST)) {
            usernameToken.setPasswordType(PASSWORD_DIGEST);
            usernameToken.setUserInfo(username, password);
            usernameToken.addCreated();
            usernameToken.addNonce();
        } else {
            usernameToken.setPasswordType(PASSWORD_TEXT);
            usernameToken.setUserInfo(username, password);
        }
    }

    public static Object convertDocumentToString(Document document) throws Exception {
        if (document == null) {
            return ErrorCreator.createError(StringUtils.fromString(EMPTY_XML_DOCUMENT_ERROR));
        }
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return StringUtils.fromString(writer.toString());
    }
}
