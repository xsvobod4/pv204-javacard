package main.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AESCipher implements ICipher {

    private static final int BLOCK_SIZE = 16;
    private Cipher cipherAes;
    private SecretKeySpec aesKey;

    public AESCipher() {
        try {
            cipherAes = Cipher.getInstance("AES/ECB/NoPadding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Key weren't established: " + e.getMessage());
        }
    }

    @Override
    public byte[] encrypt(byte[] toEncrypt) {
        try {
            byte[] paddedData = padPKCS7(toEncrypt);
            cipherAes.init(Cipher.ENCRYPT_MODE, aesKey);
            return cipherAes.doFinal(paddedData);
        } catch (IllegalBlockSizeException
                 | BadPaddingException
                 | InvalidKeyException e) {
            throw new RuntimeException("Could not encrypt data with AES due to wrong format: "
                    + e.getMessage());
        }
    }

    @Override
    public byte[] decrypt(byte[] toDecrypt) {
        try {
            cipherAes.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedData = cipherAes.doFinal(toDecrypt);
            return removePKCS7Padding(decryptedData);
        } catch (IllegalBlockSizeException
                 | BadPaddingException
                 | InvalidKeyException e) {
            throw new RuntimeException("Could not encrypt data with AES due to wrong format: "
            + e.getMessage());
        }
    }

    public void setKey(byte[] key) {
        aesKey = new SecretKeySpec(key, "AES");
    }

    private byte[] padPKCS7(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte paddingByte = (byte) paddingLength;
        byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
        Arrays.fill(paddedData, data.length, paddedData.length, paddingByte);
        return paddedData;
    }

    private byte[] removePKCS7Padding(byte[] data) {
        int paddingLength = data[data.length - 1];
        return Arrays.copyOfRange(data, 0, data.length - paddingLength);
    }
}
