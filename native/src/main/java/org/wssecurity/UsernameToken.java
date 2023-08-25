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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class UsernameToken {

    private final WSSecUsernameToken usernameToken;
    private final Signature signature;
    private final Document document;
    private X509SecToken x509SecToken = null;

    protected Document getDocument() {
        return document;
    }

    protected Signature getSignature() {
        return signature;
    }

    public UsernameToken(BObject wsSecurityHeader) {
        BHandle handle = (BHandle) wsSecurityHeader.get(StringUtils.fromString("nativeSecHeader"));
        WSSecurityHeader securityHeader = (WSSecurityHeader) handle.getValue();
        this.usernameToken = new WSSecUsernameToken(securityHeader.getWsSecHeader());
        this.signature = new Signature();
        this.document = securityHeader.getDocument();
    }

    protected WSSecUsernameToken getUsernameToken() {
        return usernameToken;
    }

//    protected X509Certificate getX509Certificate() {
//        return (x509SecToken == null) ? null : x509SecToken.getX509Certificate();
//    }
//
//    protected String getSignatureAlgorithm() {
//        return (x509SecToken == null) ? SignatureMethod.HMAC_SHA1 : x509SecToken.getSignatureAlgoName();
//    }

    protected void setX509Token(X509SecToken x509SecToken) {
        this.x509SecToken =  x509SecToken;
    }

    protected int getKeyIdentifierType() {
        return (x509SecToken == null) ? WSConstants.CUSTOM_SYMM_SIGNING : WSConstants.X509_KEY_IDENTIFIER;
    }

    protected Crypto getCryptoProperties() {
        return (x509SecToken == null) ? null : x509SecToken.getCryptoProperties();
    }

    public static Object addUsernameToken(BObject userToken, BString username, BString password,
                                          BString pwType, BString authType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        try {
            Document doc = null;
            if (authType.getValue().equals(Constants.NONE)) {
                setConfigs(usernameToken, pwType.getValue(), username.getValue(), password.getValue());
                doc = buildDocument(usernameToken, pwType.getValue());
            } else if (authType.getValue().equals(Constants.SIGNATURE)) {
                doc = addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                                            pwType.getValue(), salt, null);
            } else if (authType.getValue().equals(Constants.ENCRYPT)) {
                setConfigs(usernameToken, Constants.DIGEST, username.getValue(), password.getValue());
                buildDocument(usernameToken, pwType.getValue());
                Encryption encryption = (new Encryption(WSConstants.AES_128));
                doc = encryption.encryptEnv(usernameToken, salt);
            } else if (authType.getValue().equals(Constants.SIGN_AND_ENCRYPT)) {
                addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                                      pwType.getValue(), salt, null);
                Encryption encryption = (new Encryption(WSConstants.AES_128));
                doc = encryption.encryptEnv(usernameToken, salt);
            }
            return StringUtils.fromString(convertDocumentToString(doc));
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }

    public static Object buildToken(BObject userToken, BString username, BString password,
                                    BString pwType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        try {
            Document doc;
            if (pwType.getValue().equals(Constants.SIGNATURE)) {
                doc = addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                                            pwType.getValue(), salt, null);
            } else if (pwType.getValue().equals(Constants.ENCRYPT)) {
                setConfigs(usernameToken, Constants.DIGEST, username.getValue(), password.getValue());
                buildDocument(usernameToken, pwType.getValue());
                Encryption encryption = (new Encryption(WSConstants.AES_128));
                doc = encryption.encryptEnv(usernameToken, salt);
                return StringUtils.fromString(convertDocumentToString(doc));
            } else if (pwType.getValue().equals(Constants.SIGN_AND_ENCRYPT)) {
                addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                        pwType.getValue(), salt, null);
                Encryption encryption = (new Encryption(WSConstants.AES_128));
                doc = encryption.encryptEnv(usernameToken, salt);
            } else {
                setConfigs(usernameToken, pwType.getValue(), username.getValue(), password.getValue());
                doc = buildDocument(usernameToken, pwType.getValue());
            }
            return StringUtils.fromString(convertDocumentToString(doc));
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }

    public static Object addUsernameTokenWithKey(BObject userToken, BString username, BString password,
                                                 BString pwType, BString keyPath, BString authType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        try {
            if (authType.getValue().equals(Constants.SYMMETRIC_SIGN_AND_ENCRYPT)) {
                addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                                      pwType.getValue(), salt,
                                      usernameTokenObj.derivePrivateKey(String.valueOf(keyPath)));
                Encryption encryption = (new Encryption(WSConstants.AES_128));
                Document document = encryption.encryptEnv(usernameToken, salt);
                return StringUtils.fromString(convertDocumentToString(document));
            }
            setConfigs(usernameToken, pwType.getValue(), username.getValue(), password.getValue());
            return StringUtils.fromString(convertDocumentToString(buildDocument(usernameToken, pwType.getValue())));
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }

    public PrivateKey derivePrivateKey(String path) throws Exception {
        byte[] key = Files.readAllBytes(Paths.get(path));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        return keyFactory.generatePrivate(keySpec);
    }

//    public PublicKey derivePublicKey(String path) throws Exception {
//        byte[] key = Files.readAllBytes(Paths.get(path));
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
//        return keyFactory.generatePublic(keySpec);
//    }

    public PublicKey getPublicKey(String path) throws IOException {
        FileInputStream publicKeyFileInputStream = new FileInputStream(path);
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            publicKeyFileInputStream.close();
            throw new RuntimeException(e);
        }
        X509Certificate certificate;
        try {
            certificate = (X509Certificate) certificateFactory
                    .generateCertificate(publicKeyFileInputStream);
        } catch (CertificateException e) {
            publicKeyFileInputStream.close();
            throw new RuntimeException(e);
        }
        publicKeyFileInputStream.close();
        return certificate.getPublicKey();
    }

    public static Object addUsernameTokenWithAsymmetricKey(BObject userToken, BString username, BString password,
                                                           BString pwType, BString privateKey, BString publicKey,
                                                           BString authType) {
        BHandle handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameTokenObj = (UsernameToken) handle.getValue();
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        byte[] salt = UsernameTokenUtil.generateSalt(true);
        try {
            if (authType.getValue().equals(Constants.ASYMMETRIC_SIGN_AND_ENCRYPT)) {
                addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                        pwType.getValue(), salt, usernameTokenObj.derivePrivateKey(String.valueOf(privateKey)));
                Encryption encryption = (new Encryption(WSConstants.AES_128));
                Document document = encryption
                        .encryptEnv(usernameToken, usernameTokenObj
                                .getPublicKey(String.valueOf(publicKey)).getEncoded());
                return StringUtils.fromString(convertDocumentToString(document));
            }
            setConfigs(usernameToken, pwType.getValue(), username.getValue(), password.getValue());
            return StringUtils.fromString(convertDocumentToString(buildDocument(usernameToken, pwType.getValue())));
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }

    public static Document addSignatureWithToken(UsernameToken usernameTokenObj, String username, String password,
                                                 String passwordType, byte[] salt,
                                                 PrivateKey privateKey) throws Exception {
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        RequestData reqData = new RequestData();
        reqData.setUsername(username);
        reqData.setPwType(WSConstants.PASSWORD_TEXT); // remove?
        reqData.setSecHeader(usernameToken.getSecurityHeader());
        reqData.setWssConfig(WSSConfig.getNewInstance());
        setConfigs(usernameToken, passwordType, username, password);
        usernameToken.addDerivedKey(Constants.ITERATION);
        usernameToken.prepare(salt);
        if (privateKey != null) {
            usernameTokenObj.getSignature().buildSignature(reqData,
                    usernameTokenObj.getSignature().prepareSignature(reqData, usernameTokenObj, privateKey));
        } else {
            usernameTokenObj.getSignature().buildSignature(reqData,
                    usernameTokenObj.getSignature().prepareSignature(reqData, usernameTokenObj));
        }
        return usernameToken.build(salt);
    }

    public static Document buildDocument(WSSecUsernameToken usernameToken, String passwordType) {
//        if (Objects.equals(passwordType, Constants.SIGNATURE)) {
//            byte[] salt = UsernameTokenUtil.generateSalt(true);
//            usernameToken.prepare(salt);
//            return usernameToken.build(salt);
//        }
        return usernameToken.build();
    }

    public static void setConfigs(WSSecUsernameToken usernameToken, String passwordType,
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

    public static String convertDocumentToString(Document doc) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.toString();
    }
}
