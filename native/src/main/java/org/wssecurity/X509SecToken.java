package org.wssecurity;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;

public class X509SecToken  {
    private final Crypto crypto;
    public X509SecToken(BString filePath) {
        try {
            this.crypto = CryptoFactory.getInstance(filePath.getValue());
        } catch (WSSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static void addX509Token(BObject x509Token, BObject userToken) {
        BHandle handle = (BHandle) x509Token.get(StringUtils.fromString("nativeX509Token"));
        X509SecToken x509SecToken = (X509SecToken) handle.getValue();
        handle = (BHandle) userToken.get(StringUtils.fromString(Constants.NATIVE_UT));
        UsernameToken usernameToken = (UsernameToken) handle.getValue();
        usernameToken.setX509Token(x509SecToken);
    }

    protected Crypto getCryptoProperties() {
        return this.crypto;
    }

//    protected X509Certificate getX509Certificate() {
//        return x509Certificate;
//    }
//
//    protected String getSignatureAlgoName() {
//        return this.x509Certificate.getSigAlgName();
//    }

    public String getCustomTokenValueType() {
        return WSConstants.X509TOKEN_NS + "#X509Token";
    }
}
