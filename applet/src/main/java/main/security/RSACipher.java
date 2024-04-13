package main.security;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

public class RSACipher implements ICipher {

    private KeyPair rsaKeyPair;

    public RSACipher() {
        //TODO: Init keys here
    }

    @Override
    public byte[] encrypt(byte[] toEncrypt) {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] toDecrypt) {
        return new byte[0];
    }

    private void generateKeys() {}

    public PublicKey getPubKey() {
        return rsaKeyPair.getPublic();
    }
}
