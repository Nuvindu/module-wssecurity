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

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.wssec.Constants.NATIVE_UT;
import static org.wssec.Constants.NATIVE_X509_TOKEN;
import static org.wssec.Constants.X509;
import static org.wssec.Utils.createError;

public class X509SecToken  {

    private final Crypto crypto;
    private final X509Certificate x509Certificate;

    public X509SecToken(BString filePath) {
        FileInputStream fis;
        try {
            fis = new FileInputStream(filePath.getValue());
            CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
            this.x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
            this.crypto = CryptoFactory.getInstance(filePath.getValue());
            fis.close();
        } catch (CertificateException | WSSecurityException | IOException e) {
            throw createError(e.getMessage());
        }
    }

    protected X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public static void addX509Token(BObject x509Token, BObject userToken) {
        BHandle handle = (BHandle) x509Token.get(StringUtils.fromString(NATIVE_X509_TOKEN));
        X509SecToken x509SecToken = (X509SecToken) handle.getValue();
        handle = (BHandle) userToken.get(StringUtils.fromString(NATIVE_UT));
        UsernameToken usernameToken = (UsernameToken) handle.getValue();
        usernameToken.setX509Token(x509SecToken);
    }

    protected Crypto getCryptoProperties() {
        return this.crypto;
    }
}
