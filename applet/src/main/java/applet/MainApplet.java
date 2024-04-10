package applet;

import java.util.Arrays;

import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import javacard.framework.*;

public class MainApplet extends Applet implements MultiSelectable {
	/**
	 * TODO: fix state model (secondary state check) - teď zakomentován, protože neprošlo nic
	 *
	 * */

	private static final byte INS_LIST_SECRETS = (byte) 0xD7;
	private static final byte INS_GET_SECRET_VALUE = (byte) 0x11;
	private static final byte INS_GET_STATE = (byte) 0x1C;
	static final byte INS_VERIFY_PIN = (byte) 0x1D;
	static final byte INS_CHANGE_PIN = (byte) 0xC2;
	private static final byte INS_SC_INIT = (byte) 0xE2;
	static final byte INS_SET_SECRET = (byte) 0xD3;
	private static final byte INS_SC_KEYS_INIT = (byte) 0xE2;
	private static final byte INS_SC_GET_KEY = (byte) 0xD2;

	private static final short MAX_SECRET_COUNT = (short) 63;
	private static final short MAX_SECRET_NAME_LENGTH = (short) 20;
	static final short MAX_SECRET_VALUE_LENGTH = (short) 63;

	public final byte SECRET_NOT_FILLED = (byte) 0xC4;
	public final byte SECRET_FILLED = (byte) 0x26;

	public final byte OVERWRITE_DONT = (byte) 0x00;
	public final byte OVERWRITE_DO = (byte) 0x25;

	static final byte PIN_LENGTH = (byte) 0x04;
	static final byte PIN_MAX_RETRIES = (byte) 0x03;
	private final byte[] DEFAULT_PIN = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};

	private final byte[] SECOND_PIN = {(byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x04};

	//PIN1 and PIN2 default offsets
	private final short[] PIN_DEFAULT_OFFSETS = {0x05, 0x09, 0x09, 0x0D};

	private final byte RTR_PIN_SUCCESS = (byte) 0x90;
	private final byte RTR_PIN_FAILED = (byte) 0xCF;

	//Content of secrets
	private SecretStore[] secretValues;
	private byte[] secretStatus;
	private short secretCount;

	private OwnerPIN pin;
	private StateModel stateModel; // Instance of StateModel


	//stuff connected with secure channel
	private byte[] RSAKeyBytes = new byte[512];
	private AESKey aesKey;
	private Cipher rsaCipher;
	private byte[] aesKeyEncrypted;
	private Cipher aesCipherEnc;
	private Cipher aesCipherDec;
	private static final short RSA_MODULUS_LENGTH = 128; // Length of RSA modulus in bytes
	private static final short RSA_MODULUS_LENGTH_512 = 512; // Length of RSA modulus in bytes

	private static final short AES_KEY_SIZE_BYTES = 16; // AES key size in bytes
	private final byte[] exponentBytes = {0x01, 0x00, 0x01};
	private RandomData rng;
	private static final short BLOCK_SIZE = 16;


	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new MainApplet(bArray, bOffset, bLength);
	}

	protected MainApplet(byte[] bArray, short bOffset, byte bLength) {
		//first initiate in state_applet_uploaded
		stateModel = new StateModel(StateModel.STATE_APPLET_UPLOADED);

		//Secure channel stuff
		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		// generateRandomAESKey(aesKey);
		rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		aesKeyEncrypted = new byte[512];

		secretValues = new SecretStore[MAX_SECRET_COUNT];
		secretStatus = new byte[MAX_SECRET_COUNT];

		for (short i = (short) 0; i < MAX_SECRET_COUNT; i++) {
			secretValues[i] = new SecretStore();
		}

		for (short i = (short) 0; i < MAX_SECRET_COUNT; i++) {
			secretStatus[i] = SECRET_NOT_FILLED;
		}

		secretCount = 0;

		pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
		pin.update(DEFAULT_PIN, (short) 0, PIN_LENGTH);

		// Hardcoded secret names and values
        // Just for testing, Should be deleted in 1.0
		Util.arrayCopyNonAtomic(new byte[]{'S', 'e', 'c', 'r', 'e', 't', '1'},
				(short) 0,
				secretValues[(short) 0x00].secretValue,
				(short) 0,
				(short) 7);

		secretValues[(short) 0x00].setLength((short) 7);
		secretStatus[(short) 0x00] = SECRET_FILLED;
		secretCount++;

		Util.arrayCopyNonAtomic(new byte[]{'S', 'e', 'c', 'r', 'e', 't', '2'},
				(short) 0,
				secretValues[(short) 0x01].secretValue,
				(short) 0,
				(short) 7);

		secretValues[(short) 0x01].setLength((short) 7);
		secretStatus[(short) 0x01] = SECRET_FILLED;
		secretCount++;

		Util.arrayCopyNonAtomic(new byte[]{'S', 'e', 'c', 'r', 'e', 't', '3'},
				(short) 0,
				secretValues[(short) 0x02].secretValue,
				(short) 0,
				(short) 7);

		secretValues[(short) 0x02].setLength((short) 7);
		secretStatus[(short) 0x02] = SECRET_FILLED;
		secretCount++;

		// more state changes just for demo purposes
		// stateModel.setSecondaryState(StateModel.SECURE_CHANNEL_ESTABLISHED);
		stateModel.changeState(StateModel.STATE_GENERATE_KEYPAIR);
		stateModel.changeState(StateModel.STATE_UNPRIVILEGED);
		// change to new state - STATE_WAIT_SC_INIT, only INIT request with Kpub can be processed

		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] apduBuffer = apdu.getBuffer();
		// short dataLength = apdu.setIncomingAndReceive();
		byte ins = apduBuffer[ISO7816.OFFSET_INS];

		// TODO: doladit tuhle logiku s pomocí state enforceru:
		//if key is empty and INS = ISN_INIT_SC -> proceed to switch, it is ok
		//if key is empty and INS =/= ISN_INIT_SC -> throw exception
		//if key is not empty and INS is ISN_INIT_SC -> proceed to switch, it is ok
		//if key not empty and ins is not ISN_INIT_SC: decrypt whole apdu buffer and proceeds to switch


		switch (ins) {
			case INS_SC_KEYS_INIT:
				// stateModel.checkAllowedFunction(StateModel.FNC_InitSecureChannel);
				initSecureChannelKeys(apdu);
				// TODO: stateModel.changeSTATE - to new state where it can only accept INS_SC_INIT or ENCRYPTED APDUs
				break;
			case INS_SC_GET_KEY:
				// stateModel.checkAllowedFunction(StateModel.FNC_InitSecureChannel);
				sendKeyToClient(apdu);
				break;
			case INS_LIST_SECRETS:
				// Check if the function is allowed in the current state
				// stateModel.checkAllowedFunction(StateModel.FNC_lookupSecretNames);
				// decryptAPDU(apduBuffer);
				listSecrets(apdu);
				break;
			case INS_GET_SECRET_VALUE:
				// demo - change state to priviledged
//				stateModel.changeState(StateModel.STATE_PRIVILEGED);
//				// Check if the function is allowed in the current state
//				stateModel.checkAllowedFunction(StateModel.FNC_lookupSecret);
				getSecretValue(apdu);
				break;
			case INS_GET_STATE:
				// Return the current state of the applet
				sendState(apdu);
				break;
			case INS_SET_SECRET:
				storeSecret(apdu);
				break;
			case INS_CHANGE_PIN:
				updatePIN(apdu);
				break;
			case INS_VERIFY_PIN:
				verifyPIN(apdu,(short) 5, (short) 9);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void initSecureChannelKeys(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();
		switch (dataLength) {
			case 220:
				System.arraycopy(apduBuffer, ISO7816.OFFSET_CDATA, RSAKeyBytes, 0, 220);
				break;
			case 200:
				System.arraycopy(apduBuffer, ISO7816.OFFSET_CDATA, RSAKeyBytes, 220, 200);
				break;
			case 92:
				System.arraycopy(apduBuffer, ISO7816.OFFSET_CDATA, RSAKeyBytes, 420, 92);
				initializeKeys();
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void initializeKeys(){
		RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, RSA_MODULUS_LENGTH_512, false);
		rsaPublicKey.setModulus(RSAKeyBytes, (short) 0, (short) 512);

		// Generate AES key
		byte[] aesKeyBytes = new byte[AES_KEY_SIZE_BYTES];
		doGenerateRandom(aesKeyBytes, (short) 0, AES_KEY_SIZE_BYTES);
		aesKey.setKey(aesKeyBytes, (short) 0);

		// Exponent value 65537
		rsaPublicKey.setExponent(exponentBytes, (short) 0, (short) exponentBytes.length);
		// Create a separate byte buffer to hold the encrypted data

		// Encrypt AES key using RSA public key
		rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
		rsaCipher.doFinal(aesKeyBytes, (short) 0, (short) aesKeyBytes.length, aesKeyEncrypted, (short) 0);
	}

	private void sendKeyToClient(APDU apdu){
		byte[] apduBuffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();

		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 256);

		byte[] partOfKey = new byte[256];

		if(apduBuffer[ISO7816.OFFSET_CDATA] == 1){
			partOfKey = Arrays.copyOfRange(aesKeyEncrypted, 0, 256);
		}
		else if (apduBuffer[ISO7816.OFFSET_CDATA] == 2) {
			partOfKey = Arrays.copyOfRange(aesKeyEncrypted, 256, aesKeyEncrypted.length);

		}
		apdu.sendBytesLong(partOfKey, (short) 0, (short) partOfKey.length);
	}


	private void doGenerateRandom(byte[] buffer, short offset, short length) {
		rng.generateData(buffer, offset, length);
	}

	private void decryptAPDU(byte[] apduBuffer) {
		try {
			// Initialize AES cipher for decryption
			Cipher aesCipherDec = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

			// Initialize AES cipher with the AES key
			aesCipherDec.init(aesKey, Cipher.MODE_DECRYPT);

			// Get the data length (excluding header)
			short dataLength = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);

			// Decrypt the data part of the APDU buffer (excluding header)
			aesCipherDec.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, dataLength, apduBuffer, ISO7816.OFFSET_CDATA);

			// Remove PKCS7 padding from the decrypted data
			byte[] decryptedData = new byte[dataLength];
			Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, decryptedData, (short) 0, dataLength);
			decryptedData = removePKCS7Padding(decryptedData, dataLength);

			// Update the data in the APDU buffer with the decrypted and unpadded data
			short newDataLength = (short) decryptedData.length;
			Util.arrayCopyNonAtomic(decryptedData, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA, newDataLength);

			// Update the Lc field in the APDU header with the new data length
			apduBuffer[ISO7816.OFFSET_LC] = (byte) newDataLength;

			// Clear the remaining bytes in the buffer (padding bytes)
			for (short i = (short) (ISO7816.OFFSET_CDATA + newDataLength); i < apduBuffer.length; i++) {
				apduBuffer[i] = 0x00;
			}

		} catch (CryptoException e) {
			// Handle decryption error
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}

	private byte[] encryptAPDU(byte[] data) {
		try {
			data = padPKCS7(data);
			// Create AES cipher instance for encryption
			Cipher aesCipherEnc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

			// Initialize AES cipher with the AES key
			aesCipherEnc.init(aesKey, Cipher.MODE_ENCRYPT);

			// Encrypt the data
			aesCipherEnc.doFinal(data, (short) 0, (short) data.length, data, (short) 0);

			return data; // Return the modified data array after encryption
		} catch (CryptoException e) {
			// Handle encryption error
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return null; // Return null in case of error
		}
	}

	private byte[] padPKCS7(byte[] data) {
		// Calculate the number of padding bytes needed
		short remainder = (short) (data.length % BLOCK_SIZE);
		short paddingLength = remainder == 0 ? 0 : (short) (BLOCK_SIZE - remainder);

		// Create a new byte array to hold the padded data
		byte[] paddedData = new byte[(short) (data.length + paddingLength)];

		// Copy the original data to the paddedData array
		Util.arrayCopyNonAtomic(data, (short) 0, paddedData, (short) 0, (short) data.length);

		// Add padding bytes
		for (short i = (short) (data.length); i < (short) (data.length + paddingLength); i++) {
			paddedData[i] = (byte) paddingLength; // Set the padding byte value
		}

		return paddedData;
	}


	private byte[] removePKCS7Padding(byte[] data, short dataLength) {
		// Calculate the last byte, which represents the padding length
		short paddingLength = (short) (data[(short) (dataLength - 1)] & 0xFF);

		// Ensure padding length is valid
		if (paddingLength <= 0 || paddingLength > 16) { // Assuming each block is 16 bytes
			// Padding is incorrect, throw exception or handle accordingly
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		// Calculate the length of the unpadded data
		short unpaddedLength = (short) (dataLength - paddingLength);

		// Create a new byte array to hold the unpadded data
		byte[] unpaddedData = new byte[unpaddedLength];

		// Copy the unpadded data from the original buffer
		Util.arrayCopyNonAtomic(data, (short) 0, unpaddedData, (short) 0, unpaddedLength);

		return unpaddedData;
	}

	private void listSecrets(APDU apdu) {
		// Send response
		apdu.setOutgoing();
		//apdu.setOutgoingLength(MAX_SECRET_COUNT);

		byte[] secretStatusCopy = new byte[MAX_SECRET_COUNT];
		Util.arrayCopyNonAtomic(secretStatus, (short) 0, secretStatusCopy, (short) 0, MAX_SECRET_COUNT);
		secretStatusCopy = encryptAPDU(secretStatusCopy); // Encrypt the data and get the modified array

		short encryptedLength = (short) secretStatusCopy.length;
		apdu.setOutgoingLength(encryptedLength); // Set outgoing length to the size of encrypted data

		apdu.sendBytesLong(secretStatusCopy, (short) 0, MAX_SECRET_COUNT);
	}

	public boolean select(boolean b) {
		return true;
	}

	public void deselect(boolean b) {

		if (stateModel.getState() != StateModel.STATE_APPLET_UPLOADED) {
			stateModel.changeState(StateModel.STATE_UNPRIVILEGED);
		}
		// clear key?
		aesKey.clearKey();
	}

	//TODO: Add value to the SecretStore array and set the secret (at the same index) to filled status
	private void storeSecret(APDU apdu) {

		byte[] apduBuffer = apdu.getBuffer();
		short index = apduBuffer[ISO7816.OFFSET_P1];
		short length = apdu.getIncomingLength();
		byte overwrite = apduBuffer[ISO7816.OFFSET_P2];

		// Verify PIN
		if (verifyPIN(apdu, ISO7816.OFFSET_CDATA, PIN_DEFAULT_OFFSETS[1]) != RTR_PIN_SUCCESS) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		// Check if the store is full
		if (secretCount >= MAX_SECRET_COUNT) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		// Check if the index is out of range
		if (index >= MAX_SECRET_COUNT) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		// Check if index is a negative number
		if (index < 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		if (overwrite == OVERWRITE_DONT && secretStatus[index] == SECRET_FILLED) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		short secretLength = (short) (apdu.getIncomingLength() - (short) PIN_LENGTH);

		// Check if the value being stored is too long
		if (secretLength > MAX_SECRET_VALUE_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Store the value
		Util.arrayCopyNonAtomic(apduBuffer,
				PIN_DEFAULT_OFFSETS[2],
				secretValues[index].secretValue,
				(short) 0,
				secretLength);
		secretValues[index].setLength(secretLength);
		secretStatus[index] = SECRET_FILLED;
		secretCount++;
	}

	private void getSecretValue(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		decryptAPDU(apduBuffer);
		// Verify PIN
		if (verifyPIN(apdu, ISO7816.OFFSET_CDATA, PIN_DEFAULT_OFFSETS[1]) != RTR_PIN_SUCCESS) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		byte queryKey = apduBuffer[ISO7816.OFFSET_P1];

		// Check if the data length is at least one byte
		if (queryKey < 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Check if the query key is out of range
		if (queryKey >= MAX_SECRET_COUNT) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Check if the secret is not filled
		if (secretStatus[queryKey] == SECRET_NOT_FILLED) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		 byte[] SecretValue = secretValues[queryKey].secretValue;

		if (SecretValue == null) {
			// Handle the case where encryption failed
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		byte[] encryptedSecretValue = encryptAPDU(SecretValue);

		apdu.setOutgoing();
		apdu.setOutgoingLength( (short) encryptedSecretValue.length);
		apdu.sendBytesLong(encryptedSecretValue , (short) 0, (short) encryptedSecretValue.length);
	}

	private void sendState(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short currentState = stateModel.getState();
		Util.setShort(buffer, (short) 0, currentState);
		apdu.setOutgoingAndSend((short) 0, (short) 2); // Assuming state is represented by a short (2 bytes)
	}

	// Method to verify PIN
	private byte verifyPIN(APDU apdu, short startInter, short endInter) {

		byte[] apduBuffer = apdu.getBuffer();

		return pin.check(apduBuffer, startInter, PIN_LENGTH)
				? RTR_PIN_SUCCESS : RTR_PIN_FAILED;
	}

	private void updatePIN(APDU apdu) {

		byte[] apduBuffer = apdu.getBuffer();

		if (verifyPIN(apdu,PIN_DEFAULT_OFFSETS[0], PIN_DEFAULT_OFFSETS[1]) != RTR_PIN_SUCCESS)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		//stateModel.changeState(StateModel.STATE_PRIVILEGED);

		try {
			pin.update(apduBuffer, PIN_DEFAULT_OFFSETS[2], PIN_LENGTH);
		} catch (PINException e) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		//stateModel.changeState(StateModel.STATE_UNPRIVILEGED);

//		stateModel.changeState(StateModel.STATE_UNPRIVILEGED);
		ISOException.throwIt(ISO7816.SW_NO_ERROR);
	}
}
