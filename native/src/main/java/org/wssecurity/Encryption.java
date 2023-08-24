package org.wssecurity;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Document;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

public class Encryption {

    private final String encryptionAlgorithm;
    public Encryption(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public Document encryptEnv(WSSecUsernameToken usernameToken, byte[] rawKey) throws WSSecurityException {
        Init.init();
        JCEMapper.registerDefaultAlgorithms();
        WSSecDKEncrypt encryptionBuilder = new WSSecDKEncrypt(usernameToken.getSecurityHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(encryptionAlgorithm);
        encryptionBuilder.setTokenIdentifier(usernameToken.getId());
        encryptionBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        usernameToken.addDerivedKey(Constants.ITERATION);
        Document encryptedDoc = encryptionBuilder.build(rawKey);
        usernameToken.prependToHeader();
        return encryptedDoc;
    }

    public Document encryptEnvelope(WSSecUsernameToken usernameToken,
                                    byte[] rawKey, Crypto crypto) throws WSSecurityException {
        WSSecEncrypt encryptionBuilder = new WSSecEncrypt(usernameToken.getSecurityHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(encryptionAlgorithm);
        encryptionBuilder.setCustomEKTokenId(usernameToken.getId());
        encryptionBuilder.setCustomEKTokenValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        usernameToken.addDerivedKey(Constants.ITERATION);
        SecretKey secretKey1 = KeyUtils.prepareSecretKey(encryptionAlgorithm, rawKey);
        Document encryptedDoc = encryptionBuilder.build(crypto, secretKey1);
        usernameToken.prependToHeader();
        return encryptedDoc;
    }

    public Document encryptWithSymmetricKey(UsernameToken usernameToken,
                                            byte[] rawKey) throws WSSecurityException, NoSuchAlgorithmException {
        WSSecEncrypt encryptionBuilder = new WSSecEncrypt(usernameToken.getUsernameToken().getSecurityHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(encryptionAlgorithm);
        encryptionBuilder.setCustomEKTokenId(usernameToken.getUsernameToken().getId());
        encryptionBuilder.setCustomEKTokenValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        usernameToken.getUsernameToken().addDerivedKey(Constants.ITERATION);
        SecretKey secretKey1 = KeyUtils.prepareSecretKey(encryptionAlgorithm, rawKey);
        Document encryptedDoc = encryptionBuilder.build(usernameToken.getCryptoProperties(), secretKey1);
        usernameToken.getUsernameToken().prependToHeader();
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        keyPair.getPublic();
//        X509Certificate x509Certificate = ;
//        x509Certificate.getPublicKey()
        return encryptedDoc;
    }
}
