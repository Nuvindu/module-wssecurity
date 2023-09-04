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
import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import static org.wssecurity.Utils.createError;

public class UsernameToken {

    private final WSSecUsernameToken usernameToken;

    private String username;
    private String password;
    private String passwordType;
    private String signAlgo;
    private String encAlgo;
    private final Document document;
    private X509SecToken x509SecToken = null;

    protected Document getDocument() {
        return document;
    }

    public UsernameToken(BObject wsSecurityHeader, BString signatureAlgo, BString encryptionAlgo) {
        BHandle handle = (BHandle) wsSecurityHeader.get(StringUtils.fromString(Constants.NATIVE_SEC_HEADER));
        WSSecurityHeader securityHeader = (WSSecurityHeader) handle.getValue();
        this.usernameToken = new WSSecUsernameToken(securityHeader.getWsSecHeader());
        this.signAlgo = signatureAlgo.getValue();
        this.encAlgo = encryptionAlgo.getValue();
        this.document = securityHeader.getDocument();
//        this.encryption = new Encryption(encryptionAlgo.getValue());
    }

    public static void setUsername(BObject userToken, BString username) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        usernameTokenObj.setUsername(username.getValue());
    }

    public static void setPassword(BObject userToken, BString password) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        usernameTokenObj.setPassword(password.getValue());
    }

    public static void setPasswordType(BObject userToken, BString passwordType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
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

    private static Result getResult(BObject userToken, BObject encryption, BObject signature) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        String username = usernameTokenObj.getUsername();
        String password = usernameTokenObj.getPassword();
        String passwordType = usernameTokenObj.getPasswordType();
        Signature signatureObj = null;
        Encryption encryptionObj = null;
        if (signature != null) {
            handle = (BHandle) signature.get(StringUtils.fromString(Constants.NATIVE_SIGNATURE));
            signatureObj = (Signature) handle.getValue();
        }
        if (encryption != null) {
            handle = (BHandle) encryption.get(StringUtils.fromString(Constants.NATIVE_ENCRYPTION));
            encryptionObj = (Encryption) handle.getValue();
        }
        return new Result(usernameTokenObj, usernameToken, username, password, passwordType, signatureObj,
                encryptionObj);
    }

    private record Result(UsernameToken usernameTokenObj, WSSecUsernameToken usernameToken, String username,
                          String password, String passwordType, Signature signatureObj, Encryption encryptionObj) {
    }

    public static Document setSignatureHeaderData(UsernameToken usernameTokenObj, String signatureAlgorithm,
                                                  byte[] salt, byte[] signature) throws Exception {
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        RequestData reqData = new RequestData();
        reqData.setSecHeader(usernameToken.getSecurityHeader());
        reqData.setWssConfig(WSSConfig.getNewInstance());
        setUTChildElements(usernameToken, usernameTokenObj.getPasswordType(), usernameTokenObj.getUsername(),
                           usernameTokenObj.getPassword());
        usernameToken.prepare(salt);
        if (signature != null) {
            WSSecurityUtils.buildSignature(reqData,
                    WSSecurityUtils.prepareSignature(reqData, usernameTokenObj, signature, signatureAlgorithm));
        } else {
            WSSecurityUtils.buildSignature(reqData,
                    WSSecurityUtils.prepareSignature(reqData, usernameTokenObj, null, signatureAlgorithm));
        }
        Document document = usernameToken.build(salt);
        WSSecurityUtils.setSignatureValue(document, signature);
        return document;
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

    protected int getKeyIdentifierType() {
        return (x509SecToken == null) ? WSConstants.CUSTOM_SYMM_SIGNING : WSConstants.X509_KEY_IDENTIFIER;
    }

    protected Crypto getCryptoProperties() {
        return (x509SecToken == null) ? null : x509SecToken.getCryptoProperties();
    }

    public PrivateKey getPrivateKey(String path) throws Exception {
        byte[] key = Files.readAllBytes(Paths.get(path));
        KeyFactory keyFactory = KeyFactory.getInstance(Constants.RSA);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        return keyFactory.generatePrivate(keySpec);
    }


    public static BArray getEncryptedData(BObject userToken) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        return ValueCreator.createArrayValue(WSSecurityUtils.getEncryptedData(usernameTokenObj.getDocument()));
    }

    public static BArray getSignatureData(BObject userToken) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        return ValueCreator.createArrayValue(WSSecurityUtils.getSignatureValue(usernameTokenObj.getDocument()));
    }

//    public static Object populateHeaderData(BObject userToken) {
//        Result result = getResult(userToken, null, null);
//        try {
//            setUTChildElements(result.usernameToken(), result.passwordType(), result.username(), result.password());
//            return result.usernameToken().build();
//        } catch (Exception e) {
//            return createError(e.getMessage());
//        }
//    }

    public static Object populateHeaderDataWithSignAndEncrypt(BObject userToken,
                                                              BObject signature, BObject encryption) {
        Result result = getResult(userToken, encryption, signature);
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        Document xmlDocument;
        try {
            xmlDocument = addSignatureWithToken(result.usernameTokenObj(), result.username(), result.password(),
                    result.passwordType(), salt, result.signatureObj().getSignatureValue());
            WSSecurityUtils.setSignatureValue(xmlDocument, result.signatureObj().getSignatureValue());
            xmlDocument = WSSecurityUtils.encryptEnv(result.usernameToken(),
                                                     result.encryptionObj().getEncryptionAlgorithm(), salt);
            WSSecurityUtils.setEncryptedData(xmlDocument, result.encryptionObj().getEncryptedData());
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Object populateHeaderDataWithSignature(BObject userToken, BObject signature) {
        Result result = getResult(userToken, null, signature);
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        Document xmlDocument;
        try {
            xmlDocument = addSignatureWithToken(result.usernameTokenObj(), result.username(), result.password(),
                    result.passwordType(), salt, result.signatureObj().getSignatureValue());
            WSSecurityUtils.setSignatureValue(xmlDocument, result.signatureObj().getSignatureValue());
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Object populateHeaderDataWithEncryption(BObject userToken, BObject encryption) {
        Result result = getResult(userToken, encryption, null);
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        Document xmlDocument;
        try {
            xmlDocument = WSSecurityUtils.encryptEnv(result.usernameToken(),
                    result.encryptionObj().getEncryptionAlgorithm(), salt);
            WSSecurityUtils.setEncryptedData(xmlDocument, result.encryptionObj().getEncryptedData());
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }
    public static Object populateHeaderData(BObject userToken, BString username, BString password,
                                          BString pwType, BArray encryptedData, BArray signatureValue,
                                          BString authType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        Document xmlDocument;
        try {
            switch (authType.getValue()) {
                case Constants.NONE -> {
                    setUTChildElements(usernameToken, pwType.getValue(), username.getValue(), password.getValue());
                    xmlDocument = usernameToken.build();
                }
                case Constants.SIGNATURE -> {
                    xmlDocument = addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                            pwType.getValue(), salt, signatureValue.getByteArray());
                    WSSecurityUtils.setSignatureValue(xmlDocument, signatureValue.getByteArray());
                }
                case Constants.ENCRYPT -> {
                    setUTChildElements(usernameToken, Constants.DIGEST, username.getValue(), password.getValue());
                    usernameToken.build();
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(), salt);
                    WSSecurityUtils.setEncryptedData(xmlDocument, encryptedData.getByteArray());
                }
                case Constants.SIGN_AND_ENCRYPT -> {
                    addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                            pwType.getValue(), salt, signatureValue.getByteArray());
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(), salt);
                    WSSecurityUtils.setEncryptedData(xmlDocument, encryptedData.getByteArray());
                    WSSecurityUtils.setSignatureValue(xmlDocument, signatureValue.getByteArray());
                }
                case Constants.SYMMETRIC_SIGN_AND_ENCRYPT -> {
                    addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                                          pwType.getValue(), salt, "x".getBytes(StandardCharsets.UTF_8));
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(),
                                                             "x".getBytes(StandardCharsets.UTF_8));
                }
                case Constants.ASYMMETRIC_SIGN_AND_ENCRYPT -> {
                    addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(), pwType.getValue(),
                                          salt, "x".getBytes(StandardCharsets.UTF_8));
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(),
                                                             "y".getBytes(StandardCharsets.UTF_8));
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

    public static Document addSignatureWithToken(UsernameToken usernameTokenObj, String username, String password,
                                                 String passwordType, byte[] salt,
                                                 byte[] key) throws Exception {
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        RequestData reqData = new RequestData();
        reqData.setSecHeader(usernameToken.getSecurityHeader());
        reqData.setWssConfig(WSSConfig.getNewInstance());
        setUTChildElements(usernameToken, passwordType, username, password);
        usernameToken.prepare(salt);
        if (key != null) {
            WSSecurityUtils.buildSignature(reqData,
                    WSSecurityUtils.prepareSignature(reqData, usernameTokenObj, key,
                                                     usernameTokenObj.getSignAlgo()));
        } else {
            WSSecurityUtils.buildSignature(reqData,
                    WSSecurityUtils.prepareSignature(reqData, usernameTokenObj, null,
                                                     usernameTokenObj.getSignAlgo()));
        }
        Document doc = usernameToken.build(salt);
//        NodeList digestValueList = doc.getElementsByTagName("ds:DigestValue");
//        digestValueList.item(0).getFirstChild().setNodeValue("BnLWgsZS25SmiyLJwA");
        return doc;
    }

    public static void setUTChildElements(WSSecUsernameToken usernameToken, String passwordType,
                                          String username, String password) {
        if (Objects.equals(passwordType, Constants.DIGEST)) {
            usernameToken.setPasswordType(WSConstants.PASSWORD_DIGEST);
            usernameToken.setUserInfo(username, password);
            usernameToken.addCreated();
            usernameToken.addNonce();
        } else {
            usernameToken.setPasswordType(WSConstants.PASSWORD_TEXT);
            usernameToken.setUserInfo(username, password);
        }
    }

    public static Object convertDocumentToString(Document document) throws Exception {
        if (document == null) {
            return ErrorCreator.createError(StringUtils.fromString("XML Document is empty"));
        }
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return StringUtils.fromString(writer.toString());
    }
}
