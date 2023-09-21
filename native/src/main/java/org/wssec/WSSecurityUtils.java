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

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.xml.crypto.dsig.Reference;

import static org.apache.wss4j.common.WSS4JConstants.AES_128_GCM;
import static org.apache.wss4j.common.WSS4JConstants.HMAC_SHA1;
import static org.apache.wss4j.dom.WSConstants.CUSTOM_KEY_IDENTIFIER;
import static org.apache.wss4j.dom.WSConstants.X509_KEY_IDENTIFIER;
import static org.wssec.Constants.CIPHER_VALUE_TAG;
import static org.wssec.Constants.ENCRYPTION_METHOD_TAG;
import static org.wssec.Constants.ITERATION;
import static org.wssec.Constants.NAMESPACE_URI_ENC;
import static org.wssec.Constants.SIGNATURE_METHOD_TAG;
import static org.wssec.Constants.SIGNATURE_VALUE_TAG;

public class WSSecurityUtils {

    public static Document encryptEnvelope(WSSecUsernameToken usernameToken,
                                           byte[] rawKey) throws WSSecurityException {
        Init.init();
        JCEMapper.registerDefaultAlgorithms();
        WSSecDKEncrypt encryptionBuilder = new WSSecDKEncrypt(usernameToken.getSecurityHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(AES_128_GCM);
        return encryptionBuilder.build(rawKey);
    }

    public static WSSecSignature prepareSignature(RequestData reqData, UsernameToken usernameToken,
                                                  boolean useDerivedKey) throws WSSecurityException {
        WSSecSignature sign = new WSSecSignature(reqData.getSecHeader());
        byte[] key = UsernameTokenUtil.generateDerivedKey(usernameToken.getPassword(),
                                                          UsernameTokenUtil.generateSalt(true), ITERATION);
        if (useDerivedKey) {
            usernameToken.getUsernameToken().addDerivedKey(ITERATION);
        }
        sign.setSecretKey(key);
        sign.setWsDocInfo(reqData.getWsDocInfo());
        sign.setSignatureAlgorithm(HMAC_SHA1);
        if (usernameToken.getX509SecToken() != null) {
            sign.setKeyIdentifierType(X509_KEY_IDENTIFIER);
            sign.setX509Certificate(usernameToken.getX509SecToken().getX509Certificate());
        } else {
            sign.setKeyIdentifierType(CUSTOM_KEY_IDENTIFIER);
        }
        sign.prepare(usernameToken.getCryptoProperties());
        return sign;
    }

    public static void buildSignature(RequestData reqData, WSSecSignature sign) throws Exception {
        List<WSEncryptionPart> parts;
        parts = new ArrayList<>(1);
        Document doc = reqData.getSecHeader().getSecurityHeaderElement().getOwnerDocument();
        parts.add(WSSecurityUtil.getDefaultEncryptionPart(doc));
        List<Reference> referenceList = sign.addReferencesToSign(parts);
        sign.computeSignature(referenceList);
        reqData.getSignatureValues().add(sign.getSignatureValue());
    }

    public static void setSignatureValue(Document doc, byte[] signature, String algorithm) {
        doc.getElementsByTagName(SIGNATURE_METHOD_TAG)
                .item(0).getAttributes().item(0).setNodeValue(algorithm);
        NodeList digestValueList = doc.getElementsByTagName(SIGNATURE_VALUE_TAG);
        digestValueList.item(0).getFirstChild().setNodeValue(Base64.getEncoder().encodeToString(signature));
    }

    public static byte[] getSignatureValue(Document doc) {
        String signature = doc.getElementsByTagName(SIGNATURE_VALUE_TAG).item(0).getFirstChild().getNodeValue();
        return Base64.getDecoder().decode(signature);
    }

    public static void setEncryptedData(Document doc, byte[] encryptedData, String algorithm) {
        Element cipherDataElement = (Element) doc
                .getElementsByTagNameNS(NAMESPACE_URI_ENC, CIPHER_VALUE_TAG).item(0);
        cipherDataElement.getFirstChild().setNodeValue(Base64.getEncoder().encodeToString(encryptedData));
        doc.getElementsByTagName(ENCRYPTION_METHOD_TAG).item(0).getAttributes().item(0)
                .setNodeValue(algorithm);
    }

    public static byte[] getEncryptedData(Document document) {
        String encryptedText = document
                .getElementsByTagNameNS(NAMESPACE_URI_ENC, CIPHER_VALUE_TAG).item(0)
                .getFirstChild().getNodeValue();
        return Base64.getDecoder().decode(encryptedText);
    }
}
