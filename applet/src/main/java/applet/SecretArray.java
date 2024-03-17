package applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class SecretArray {
    public byte[] secret;
    public short length;
    public static final short MAX_SECRET_VALUE_LENGTH = (short) 20;

    public SecretArray() {
        secret = new byte[MAX_SECRET_VALUE_LENGTH];
    }

    //public SecretArray(byte[] secret) {
    //    setSecret(secret);
    //}

    public byte[] getSecret() {
        return secret;
    }

    public void setLength(short length) {
        this.length = length;
    }

    public short getLength() {
        return length;
    }
}
