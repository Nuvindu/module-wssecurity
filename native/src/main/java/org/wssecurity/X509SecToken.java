package org.wssecurity;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.dom.WSConstants;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X509SecToken  {
    private final Crypto crypto;
    private final X509Certificate x509Certificate;
    public X509SecToken(BString filePath) throws Exception {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filePath.getValue());
            CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.X509);
            this.x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
            this.crypto = CryptoFactory.getInstance(filePath.getValue());
        } finally {
            assert fis != null;
            fis.close();
        }
    }

    protected X509Certificate getX509Certificate() {
        return x509Certificate;
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

    public String getCustomTokenValueType() {
        return WSConstants.X509TOKEN_NS + "#X509Token";
    }
}
