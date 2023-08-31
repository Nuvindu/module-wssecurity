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

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.EncryptionUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;
import javax.xml.crypto.dsig.Reference;

public class WSSecurityUtils {

    public static WSDataRef decryptEnv(UsernameToken usernameToken, String encAlgo,
                                             byte[] rawKey) throws WSSecurityException {

        WSSConfig.init();
//        WSSecurityEngine engine = new WSSecurityEngine();
//
//        RequestData requestData = new RequestData();
        String text = "http://www.w3.org/2001/04/xmlenc#";
        NodeList encryptedDataNodes = usernameToken
                .getDocument()
                .getElementsByTagNameNS(text, "EncryptedData");
        Element encryptedDataElement = (Element) encryptedDataNodes.item(0);

//        Element cipherDataElement = (Element) usernameToken
//                .getDocument()
//                .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "CipherData")
//                .item(0);

        // Convert the <xenc:CipherData> content into an org.w3c.dom.Element
//        Element encryptedElement = (Element) cipherDataElement.getFirstChild();

//        WSHandlerResult decryptedElement = engine.processSecurityHeader(usernameToken.getDocument(), requestData);
        String dataRefURI = "ED-66c68d42-349a-4e97-8e2a-92430af86e3d";

        SecretKey secretKey = KeyUtils.prepareSecretKey(WSConstants.AES_128_GCM, rawKey);
        WSDataRef wsDataRef = EncryptionUtils
                .decryptEncryptedData(usernameToken.getDocument(), dataRefURI,
                        encryptedDataElement, secretKey, encAlgo, null);
        return wsDataRef;
    }
    public static Document encryptEnv(WSSecUsernameToken usernameToken, String encAlgo,
                                      byte[] rawKey) throws WSSecurityException {
        WSSecDKEncrypt encryptionBuilder = new WSSecDKEncrypt(usernameToken.getSecurityHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(encAlgo);
        Document doc = encryptionBuilder.build(rawKey);
//        String text = "http://www.w3.org/2001/04/xmlenc#";
//        NodeList encryptedDataNodes =
//                doc.getElementsByTagNameNS(text, "EncryptedData");
//        Element encryptedDataElement = (Element) encryptedDataNodes.item(0);

//        Element cipherDataElement =
//                (Element) doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "CipherValue")
//                        .item(0);
//        cipherDataElement.getFirstChild().setNodeValue("qeKDCZF26xM4lPFxTwuFn7Lo1zqim9");
        //        usernameToken.prependToHeader();
        return doc;
    }

    public static WSSecSignature prepareSignature(RequestData reqData, UsernameToken usernameToken,
                                                  byte[] key, String algorithm) throws WSSecurityException {
        WSSecSignature sign = new WSSecSignature(reqData.getSecHeader());
        sign.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        sign.setAddInclusivePrefixes(reqData.isAddInclusivePrefixes());
        sign.setCustomTokenId(usernameToken.getUsernameToken().getId());
        usernameToken.getUsernameToken().addDerivedKey(Constants.ITERATION);
        byte [] secretKey = usernameToken.getUsernameToken()
                .getDerivedKey(UsernameTokenUtil.generateSalt(reqData.isUseDerivedKeyForMAC()));
        sign.setSecretKey(secretKey);
//        sign.setSecretKey(key);
        sign.setWsDocInfo(new WSDocInfo(usernameToken.getDocument()));
        sign.setKeyIdentifierType(usernameToken.getKeyIdentifierType());
        sign.setSignatureAlgorithm(algorithm);
        if (usernameToken.getX509SecToken() != null) {
            sign.setX509Certificate(usernameToken.getX509SecToken().getX509Certificate());
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

    public static void setSignatureValue(Document doc, byte[] signature) {
        NodeList digestValueList = doc.getElementsByTagName("ds:DigestValue");
        digestValueList.item(0).getFirstChild().setNodeValue(Base64.getEncoder().encodeToString(signature));
    }

    public static byte[] getSignatureValue(Document doc) {
        NodeList digestValueList = doc.getElementsByTagName("ds:DigestValue");
        String encryptedText = digestValueList.item(0).getFirstChild().getNodeValue();
        return Base64.getDecoder().decode(encryptedText);
    }

    public static void setEncryptedData(Document doc, byte[] encryptedData) {
        String nameSpaceURI = "http://www.w3.org/2001/04/xmlenc#";
        String cipherValue = "CipherValue";
        Element cipherDataElement = (Element) doc.getElementsByTagNameNS(nameSpaceURI, cipherValue).item(0);
        cipherDataElement.getFirstChild().setNodeValue(Base64.getEncoder().encodeToString(encryptedData));
    }

    public static byte[] getEncryptedData(Document doc) {
        String nameSpaceURI = "http://www.w3.org/2001/04/xmlenc#";
        String cipherValue = "CipherValue";
        Element cipherDataElement = (Element) doc.getElementsByTagNameNS(nameSpaceURI, cipherValue).item(0);
        String encryptedText = cipherDataElement.getFirstChild().getNodeValue();
        return Base64.getDecoder().decode(encryptedText);
    }

//    private static byte[] deriveSecretKey(RequestData reqData,
//                                          UsernameToken usernameToken, Key key) throws WSSecurityException {
//        byte[] secretKey;
//        if (key != null) {
//            secretKey = key.getEncoded();
//        } else if (usernameToken.getX509SecToken() != null) {
//            secretKey = usernameToken.getX509SecToken().getX509Certificate().getPublicKey().getEncoded();
//        } else {
//            usernameToken.getUsernameToken().addDerivedKey(Constants.ITERATION);
//            secretKey = usernameToken.getUsernameToken()
//                    .getDerivedKey(UsernameTokenUtil.generateSalt(reqData.isUseDerivedKeyForMAC()));
//        }
//        return secretKey;
//    }
}
