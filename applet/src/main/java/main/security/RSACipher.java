package main.security;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.util.Arrays;

public class RSACipher implements ICipher {

    private KeyPair rsaKeyPair;
    private Cipher rsaDecryptCipher;

    private static final int RSA_KEY_LENGTH = 2048;

    public RSACipher() {
        generateRSAKeyPair();
        initCipher();
    }

    //Only decryption is needed as the secure channel uses RSA
    //in one-way mode.
    @Override
    public byte[] encrypt(byte[] toEncrypt) {
        throw new NotImplementedException();
    }

    @Override
    public byte[] decrypt(byte[] toDecrypt) {
        try {
            return rsaDecryptCipher.doFinal(toDecrypt);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Wrong data format passed to RSA decryption: " +
                    e.getMessage());
        }
    }

    public byte[] getRSAModulusAsBytes() {
        byte[] modulusBytesWithSign =
                ((RSAKey) rsaKeyPair.getPublic())
                .getModulus()
                .toByteArray();
        if (modulusBytesWithSign[0] == 0) {
            return Arrays.copyOfRange(modulusBytesWithSign, 1, modulusBytesWithSign.length);
        }
        return modulusBytesWithSign;
    }

    private void generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(RSA_KEY_LENGTH);
            rsaKeyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA keys could not be created: " + e.getMessage());
        }
    }

    private void initCipher() {

        if (rsaKeyPair == null) {
            throw new RuntimeException("RSA keys are not established.");
        }

        try {
            rsaDecryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaDecryptCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
        } catch (NoSuchPaddingException
                 | NoSuchAlgorithmException
                 | InvalidKeyException e) {
            throw new RuntimeException("RSA Cipher could not be established: " + e.getMessage());
        }

    }
}
