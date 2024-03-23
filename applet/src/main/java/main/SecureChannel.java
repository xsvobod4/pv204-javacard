package main;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;

public class SecureChannel {

	KeyPair RSAKeyPair;

	private static final short RSA_KEY_LENGTH = 1024; // Length of RSA modulus in bytes


	public SecureChannel() throws Exception {
		this.RSAKeyPair = generateRSAKeyPair();
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
}
