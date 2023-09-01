package org.wssecurity;

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;

public class Encryption {
    public String encryptionAlgorithm = "";
    public byte[] encryptedData = new byte[0];

    public static void setEncryptionAlgorithm(BObject encrypt, BString encryptionAlgorithm) {
        BHandle handle = (BHandle) encrypt.get(StringUtils.fromString("nativeEncryption"));
        Encryption encryption = (Encryption) handle.getValue();
        encryption.setEncryptionAlgorithm(encryptionAlgorithm.getValue());
    }

    public static void setEncryptedData(BObject encrypt, BArray encryptedData) {
        BHandle handle = (BHandle) encrypt.get(StringUtils.fromString("nativeEncryption"));
        Encryption encryption = (Encryption) handle.getValue();
        encryption.setEncryptedData(encryptedData.getByteArray());
    }

    public static BArray getEncryptedData(BObject encrypt) {
        BHandle handle = (BHandle) encrypt.get(StringUtils.fromString("nativeEncryption"));
        Encryption encryption = (Encryption) handle.getValue();
        return ValueCreator.createArrayValue(encryption.encryptedData);
    }

    protected String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    protected void setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    protected byte[] getEncrData() {
        return encryptedData;
    }

    protected void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }
}
