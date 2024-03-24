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

	private static final short RSA_KEY_LENGTH = 1024; // Length of RSA modulus in bytes


	public SecureChannel() throws Exception {
		this.RSAKeyPair = generateRSAKeyPair();
		this.cipherAES = Cipher.getInstance("AES/ECB/PKCS5Padding");
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
		cipherAES.init(Cipher.ENCRYPT_MODE, aesKey);
		return cipherAES.doFinal(data);
	}

	public static byte[] decryptAESWithKey(SecretKeySpec aesKey, byte[] data)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		cipherAES.init(Cipher.DECRYPT_MODE, aesKey);
		return cipherAES.doFinal(data);
	}

}
