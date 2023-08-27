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
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.Reference;

public class Signature {

    private String signatureAlgorithm;

    public Signature(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    protected String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    protected void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public void buildSignature(RequestData reqData, WSSecSignature sign) throws Exception {
        List<WSEncryptionPart> parts = null;
        parts = new ArrayList<>(1);
        Document doc = reqData.getSecHeader().getSecurityHeaderElement().getOwnerDocument();
        parts.add(WSSecurityUtil.getDefaultEncryptionPart(doc));
        List<Reference> referenceList = sign.addReferencesToSign(parts);
        sign.computeSignature(referenceList);
        reqData.getSignatureValues().add(sign.getSignatureValue());
    }

    public WSSecSignature prepareSignature(RequestData reqData, UsernameToken usernameToken,
                                           Key key, String algorithm) throws WSSecurityException {
        WSSecSignature sign = new WSSecSignature(reqData.getSecHeader());
//        byte[] salt = UsernameTokenUtil.generateSalt(reqData.isUseDerivedKeyForMAC());
        sign.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        sign.setAddInclusivePrefixes(reqData.isAddInclusivePrefixes());
        sign.setCustomTokenValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
        sign.setCustomTokenId(usernameToken.getUsernameToken().getId());
        byte[] secretKey = (key != null)
                ? key.getEncoded()
                : usernameToken.getUsernameToken()
                    .getDerivedKey(UsernameTokenUtil.generateSalt(reqData.isUseDerivedKeyForMAC()));
        sign.setSecretKey(secretKey);
        sign.setWsDocInfo(new WSDocInfo(usernameToken.getDocument()));
        sign.setKeyIdentifierType(usernameToken.getKeyIdentifierType());
//        TODO - Add support for different signature methods
        sign.setSignatureAlgorithm(algorithm);
        if (usernameToken.getX509SecToken() != null) {
            sign.setX509Certificate(usernameToken.getX509SecToken().getX509Certificate());
        }
        sign.prepare(usernameToken.getCryptoProperties());
        return sign;
    }

    public static byte[] convertObjectToByteArray(Serializable object) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

        // Write the object to the object output stream
        objectOutputStream.writeObject(object);
        objectOutputStream.flush();

        // Get the byte array from the byte array output stream
        return byteArrayOutputStream.toByteArray();

    }

//    public String addElement(WSSecHeader wsSecHeader) throws Exception {
//
//        Element secHeaderElem = wsSecHeader.getSecurityHeaderElement();
//        Node nd = secHeaderElem.getOwnerDocument()
//                .createElementNS("http://schemas.xmlsoap.org/ws/2005/07/securitypolicy",
//                        "wsp:Policy");
//        secHeaderElem.appendChild(nd);
//        return UsernameToken.convertDocumentToString(secHeaderElem.getOwnerDocument());
//    }
}
