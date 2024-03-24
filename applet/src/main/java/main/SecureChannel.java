package main;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class SecureChannel {

	private KeyPair RSAKeyPair;
	private static Cipher cipherAES;

	private static final short RSA_KEY_LENGTH = 4096; // Length of RSA modulus in bytes


	public SecureChannel() throws Exception {
		this.RSAKeyPair = generateRSAKeyPair();
		this.cipherAES = Cipher.getInstance("AES/ECB/NoPadding");
	}

	public RSAPublicKey getRSAPublicKey() {
		return (RSAPublicKey) RSAKeyPair.getPublic();
	}

	public RSAPrivateKey getRSAPrivateKey() {
		return (RSAPrivateKey) RSAKeyPair.getPrivate();
	}

	public byte[] getRSAModulusAsBytes(RSAKey key) {
		byte[] modulusBytesWithSign = key.getModulus().toByteArray();
		if (modulusBytesWithSign[0] == 0) {
			return Arrays.copyOfRange(modulusBytesWithSign, 1, modulusBytesWithSign.length);
		}
		return modulusBytesWithSign;
	}

	private static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(RSA_KEY_LENGTH);
		return keyPairGenerator.generateKeyPair();
	}

	public static byte[] decryptRSAWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	public static byte[] encryptAESWithKey(SecretKeySpec aesKey, byte[] data)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] paddedData = padPKCS7(data, 16);
		cipherAES.init(Cipher.ENCRYPT_MODE, aesKey);
		return cipherAES.doFinal(paddedData);
	}

	public static byte[] decryptAESWithKey(SecretKeySpec aesKey, byte[] data)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		cipherAES.init(Cipher.DECRYPT_MODE, aesKey);
		byte[] decryptedData = cipherAES.doFinal(data);

		// Remove PKCS7 padding
		return removePKCS7Padding(decryptedData);
	}

	private static byte[] padPKCS7(byte[] data, int blockSize) {
		int paddingLength = blockSize - (data.length % blockSize);
		byte paddingByte = (byte) paddingLength;
		byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
		Arrays.fill(paddedData, data.length, paddedData.length, paddingByte);
		return paddedData;
	}

	private static byte[] removePKCS7Padding(byte[] data) {
		int paddingLength = data[data.length - 1];
		return Arrays.copyOfRange(data, 0, data.length - paddingLength);
	}

}
