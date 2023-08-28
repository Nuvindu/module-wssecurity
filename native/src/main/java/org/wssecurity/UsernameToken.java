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
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class UsernameToken {

    private final WSSecUsernameToken usernameToken;
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

    protected WSSecUsernameToken getUsernameToken() {
        return usernameToken;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public String getEncAlgo() {
        return encAlgo;
    }

//    public Encryption getEncryption() {
//        return encryption;
//    }

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

    public PublicKey getPublicKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream publicKeyFileInputStream = new FileInputStream(path);
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance(Constants.X509);
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
            byte[] key = Files.readAllBytes(Paths.get(path));
            KeyFactory keyFactory = KeyFactory.getInstance(Constants.RSA);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
            return keyFactory.generatePublic(x509EncodedKeySpec);
        }
        publicKeyFileInputStream.close();
        return certificate.getPublicKey();
    }

    public static Object addUsernameToken(BObject userToken, BString username, BString password,
                                          BString pwType, Object privateKey, Object publicKey, BString authType) {
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
                            pwType.getValue(), salt, null);
                }
                case Constants.ENCRYPT -> {
                    setUTChildElements(usernameToken, Constants.DIGEST, username.getValue(), password.getValue());
                    usernameToken.build();
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(), salt);
                }
                case Constants.SIGN_AND_ENCRYPT -> {
                    addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                            pwType.getValue(), salt, null);
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(), salt);
                }
                case Constants.SYMMETRIC_SIGN_AND_ENCRYPT -> {
                    addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(),
                            pwType.getValue(), salt, usernameTokenObj.getPublicKey(String.valueOf(publicKey)));
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(),
                                                             usernameTokenObj.getPublicKey(String.valueOf(publicKey))
                                                                     .getEncoded());
                }
                case Constants.ASYMMETRIC_SIGN_AND_ENCRYPT -> {
                    addSignatureWithToken(usernameTokenObj, username.getValue(), password.getValue(), pwType.getValue(),
                                          salt, usernameTokenObj.getPrivateKey(String.valueOf(privateKey)));
                    xmlDocument = WSSecurityUtils.encryptEnv(usernameToken, usernameTokenObj.getEncAlgo(),
                                                             usernameTokenObj.getPublicKey(String.valueOf(publicKey))
                                                                     .getEncoded());
                }
                default -> {
                    return null;
                }
            }
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return ErrorCreator.createError(StringUtils.fromString(e.getMessage()));
        }
    }

    public static Document addSignatureWithToken(UsernameToken usernameTokenObj, String username, String password,
                                                 String passwordType, byte[] salt,
                                                 Key key) throws Exception {
        WSSecUsernameToken usernameToken = usernameTokenObj.getUsernameToken();
        RequestData reqData = new RequestData();
        reqData.setSecHeader(usernameToken.getSecurityHeader());
        reqData.setWssConfig(WSSConfig.getNewInstance());
        setUTChildElements(usernameToken, passwordType, username, password);
        usernameToken.prepare(salt);
        if (key != null) {
            WSSecurityUtils.buildSignature(reqData,
                    WSSecurityUtils.prepareSignature(reqData, usernameTokenObj,
                                                                     key, usernameTokenObj.getSignAlgo()));
        } else {
            WSSecurityUtils.buildSignature(reqData,
                    WSSecurityUtils.prepareSignature(reqData, usernameTokenObj, null,
                            usernameTokenObj.getSignAlgo()));
        }
        return usernameToken.build(salt);
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
