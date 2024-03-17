package applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class SecretNameArray {
    public byte[] secretName;
    private short length;
    public static final short MAX_SECRET_VALUE_LENGTH = (short) 7;

    public SecretNameArray() {
        secretName = new byte[MAX_SECRET_VALUE_LENGTH];
    }

    //public SecretNameArray(byte[] secret) {
    //    setSecret(secret);
    //}

    public void setLength(short length) {
        this.length = length;
    }

    public short getLength() {
        return length;
    }

    public byte[] getSecret() {
        return secretName;
    }
}
