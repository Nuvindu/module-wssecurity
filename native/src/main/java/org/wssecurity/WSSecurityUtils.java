package org.wssecurity;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.Reference;

public class WSSecurityUtils {

    public Document encryptEnv(WSSecUsernameToken usernameToken, String encAlgo,
                               byte[] rawKey) throws WSSecurityException {
        WSSecDKEncrypt encryptionBuilder = new WSSecDKEncrypt(usernameToken.getSecurityHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(encAlgo);
        //        usernameToken.prependToHeader();
        return encryptionBuilder.build(rawKey);
    }

    public void buildSignature(RequestData reqData, WSSecSignature sign) throws Exception {
        List<WSEncryptionPart> parts;
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
        sign.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        sign.setAddInclusivePrefixes(reqData.isAddInclusivePrefixes());
        sign.setCustomTokenId(usernameToken.getUsernameToken().getId());
        sign.setSecretKey(deriveSecretKey(reqData, usernameToken, key));
        sign.setWsDocInfo(new WSDocInfo(usernameToken.getDocument()));
        sign.setKeyIdentifierType(usernameToken.getKeyIdentifierType());
        sign.setSignatureAlgorithm(algorithm);
        if (usernameToken.getX509SecToken() != null) {
            sign.setX509Certificate(usernameToken.getX509SecToken().getX509Certificate());
        }
        sign.prepare(usernameToken.getCryptoProperties());
        return sign;
    }

    private static byte[] deriveSecretKey(RequestData reqData,
                                          UsernameToken usernameToken, Key key) throws WSSecurityException {
        byte[] secretKey;
        if (key != null) {
            secretKey = key.getEncoded();
        } else if (usernameToken.getX509SecToken() != null) {
            secretKey = usernameToken.getX509SecToken().getX509Certificate().getPublicKey().getEncoded();
        } else {
            usernameToken.getUsernameToken().addDerivedKey(Constants.ITERATION);
            secretKey = usernameToken.getUsernameToken()
                    .getDerivedKey(UsernameTokenUtil.generateSalt(reqData.isUseDerivedKeyForMAC()));
        }
        return secretKey;
    }
}
