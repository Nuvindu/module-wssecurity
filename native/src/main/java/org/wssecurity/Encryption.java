package org.wssecurity;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.w3c.dom.Document;

public class Encryption {
    private final String encryptionAlgorithm;
    public Encryption(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public Document encryptEnv(WSSecUsernameToken usernameToken, byte[] rawKey) throws WSSecurityException {
        WSSecDKEncrypt encryptionBuilder = new WSSecDKEncrypt(usernameToken.getSecurityHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(encryptionAlgorithm);
        //        usernameToken.prependToHeader();
        return encryptionBuilder.build(rawKey);
    }
}
