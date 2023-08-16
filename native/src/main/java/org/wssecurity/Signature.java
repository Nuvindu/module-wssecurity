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
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;

public class Signature {
    private final UsernameToken usernameToken;

    public Signature(UsernameToken usernameToken) {
        this.usernameToken = usernameToken;
    }

    public Document buildSignature(RequestData reqData, WSSecSignature sign, byte[] key) throws WSSecurityException {
        List<WSEncryptionPart> parts = null;
        parts = new ArrayList<>(1);
        Document doc = reqData.getSecHeader().getSecurityHeaderElement().getOwnerDocument();
        parts.add(WSSecurityUtil.getDefaultEncryptionPart(doc));
        List<Reference> referenceList = sign.addReferencesToSign(parts);
        sign.computeSignature(referenceList);
        reqData.getSignatureValues().add(sign.getSignatureValue());
        return usernameToken.getUsernameToken().build(key);
    }

    public WSSecSignature prepareSignature(RequestData reqData,
                                           UsernameToken usernameToken) throws WSSecurityException {
        WSSecSignature sign = new WSSecSignature(reqData.getSecHeader());

        byte[] salt = UsernameTokenUtil.generateSalt(reqData.isUseDerivedKeyForMAC());
        sign.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        sign.setAddInclusivePrefixes(reqData.isAddInclusivePrefixes());
        sign.setCustomTokenValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
        sign.setCustomTokenId(usernameToken.getUsernameToken().getId());
        sign.setSecretKey(usernameToken.getUsernameToken().getDerivedKey(salt));
        sign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        sign.setUserInfo("wss40", "security");
        sign.prepare(CryptoFactory.getInstance("wss40.properties"));
        return sign;
    }
}
