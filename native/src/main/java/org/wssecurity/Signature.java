package org.wssecurity;

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;

public class Signature {
    public String signatureAlgorithm = "";
    public byte[] signatureValue = new byte[0];

    public static void setSignatureAlgorithm(BObject sign, BString signatureAlgorithm) {
        BHandle handle = (BHandle) sign.get(StringUtils.fromString("nativeSignature"));
        Signature signature = (Signature) handle.getValue();
        signature.setSignatureAlgorithm(signatureAlgorithm.getValue());
    }

    public static void setSignatureValue(BObject sign, BArray signatureValue) {
        BHandle handle = (BHandle) sign.get(StringUtils.fromString("nativeSignature"));
        Signature signature = (Signature) handle.getValue();
        signature.setSignatureValue(signatureValue.getByteArray());
    }

    public static BArray getSignatureValue(BObject sign) {
        BHandle handle = (BHandle) sign.get(StringUtils.fromString("nativeSignature"));
        Signature signature = (Signature) handle.getValue();
        return ValueCreator.createArrayValue(signature.getSignatureValue());
    }

    protected String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    protected void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    protected byte[] getSignatureValue() {
        return signatureValue;
    }

    protected void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }
}
