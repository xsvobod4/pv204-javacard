package applet;

import javacard.security.*;
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
	static final byte INS_SET_SECRET = (byte) 0xC6;
	private static final byte INS_SC_KEYS_INIT = (byte) 0xE2;
	private static final byte INS_SC_GET_KEY = (byte) 0xD2;

//	TOTO: WTF???? why *of 16
	private static final short MAX_SECRET_COUNT = (short) 48;
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
	private final short[] PIN_DEFAULT_OFFSETS = {(short) ISO7816.OFFSET_CDATA, 0x09, 0x09, 0x0D};

	private final byte RTR_PIN_SUCCESS = (byte) 0x90;
	private final byte RTR_PIN_FAILED = (byte) 0xCF;

	//Content of secrets
	private SecretStore[] secretValues;
	private byte[] secretStatus;
	private short secretCount;

	private OwnerPIN pin;
	private StateModel stateModel; // Instance of StateModel


	//stuff connected with secure channel
	private byte[] rsaKeyBytes;
	private AESKey aesKey;
	private RSAPublicKey rsaPublicKey;
	private Cipher rsaCipher;
	private byte[] aesKeyEncrypted;
	private Cipher aesCipherEnc;
	private Cipher aesCipherDec;
	private byte[] partOfKey;
	private byte[] aesKeyBytes;
	private byte[] transitentArray;

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
		aesKeyEncrypted = new byte[256];
		rsaKeyBytes = new byte[256];

		secretValues = new SecretStore[MAX_SECRET_COUNT];
		secretStatus = new byte[MAX_SECRET_COUNT];

		//Transient arrays
		short maxPossibleValue;

		if (MAX_SECRET_VALUE_LENGTH > MAX_SECRET_COUNT) {
			maxPossibleValue = MAX_SECRET_VALUE_LENGTH;
		} else {
			maxPossibleValue = MAX_SECRET_COUNT;
		}

		short remainder = (short) (AES_KEY_SIZE_BYTES + (short) ((short) ( - maxPossibleValue) % AES_KEY_SIZE_BYTES));

		partOfKey = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
		aesKeyBytes = JCSystem.makeTransientByteArray(AES_KEY_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);
		transitentArray = JCSystem.makeTransientByteArray(
				(short) (maxPossibleValue + remainder),
				JCSystem.CLEAR_ON_DESELECT);

		// Initialize AES cipher for decryption
		aesCipherDec = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		// Create AES cipher instance for encryption
		aesCipherEnc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

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
			case (short) 220:
				//myArrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, RSAKeyBytes, (short) 0, (short) 220);
				Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, rsaKeyBytes, (short) 0, (short) 220);
				break;
			case (short) 36:
				//myArrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, RSAKeyBytes, (short) 220, (short) 200);
				Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, rsaKeyBytes, (short) 220, (short) 36);
				initializeKeys();
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void initializeKeys(){

		try {
			rsaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
			rsaPublicKey.setModulus(rsaKeyBytes, (short) 0, (short) 256);
			// Exponent value 65537
			rsaPublicKey.setExponent(exponentBytes, (short) 0, (short) exponentBytes.length);
		} catch (CryptoException e) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		// Generate AES key
		//byte[] aesKeyBytes = new byte[AES_KEY_SIZE_BYTES];
		doGenerateRandom(aesKeyBytes, (short) 0, AES_KEY_SIZE_BYTES);
		aesKey.setKey(aesKeyBytes, (short) 0);
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

		//byte[] partOfKey = new byte[256]
		try {

			if (apduBuffer[ISO7816.OFFSET_CDATA] == 1) {
				//myArrayCopy(aesKeyEncrypted, ISO7816.OFFSET_CLA, partOfKey, (short) 0, (short) 256);
				Util.arrayCopyNonAtomic(aesKeyEncrypted, ISO7816.OFFSET_CLA, partOfKey, (short) 0, (short) 256);
			}

			apdu.sendBytesLong(partOfKey, (short) 0, (short) partOfKey.length);
		} catch (NegativeArraySizeException | SystemException e) {
			ISOException.throwIt((short) 1111);
		}
	}


	private void doGenerateRandom(byte[] buffer, short offset, short length) {
		rng.generateData(buffer, offset, length);
	}

	private void decryptAPDU(byte[] apduBuffer) {
		try {

			// Initialize AES cipher with the AES key
			aesCipherDec.init(aesKey, Cipher.MODE_DECRYPT);

			// Get the data length (excluding header)
			//short dataLength = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
			short dataLength = apduBuffer[ISO7816.OFFSET_LC];

			// Decrypt the data part of the APDU buffer (excluding header)
			aesCipherDec.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, dataLength, apduBuffer, ISO7816.OFFSET_CDATA);

			// Get padding length
			short newDataLength = getPKCS7PaddingLen(apduBuffer, dataLength);

			// Update the Lc field in the APDU header with the new data length
			apduBuffer[ISO7816.OFFSET_LC] = (byte) newDataLength;

			// Clear the remaining bytes in the buffer (padding bytes)
			Util.arrayFillNonAtomic(apduBuffer,
					(short) (ISO7816.OFFSET_CDATA + newDataLength),
					(short) ((short)apduBuffer.length - (short) (ISO7816.OFFSET_CDATA + newDataLength)),
					(byte) 0x00);

			//apduBuffer = apduBuffer;

		} catch (CryptoException e) {
			// Handle decryption error
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}


	private short encryptData(byte[] data, short dataLength) {
		try {

			//Creates a transient array of the length needed to encrypt the data
			//Thant means data lenght and padding lenght

			short paddingLength = (short) (AES_KEY_SIZE_BYTES + (short) ((short) ( - dataLength) % AES_KEY_SIZE_BYTES));
			short encryptedLength = (short) (dataLength + paddingLength);

			Util.arrayCopyNonAtomic(data, (short) 0, transitentArray, (short) 0, dataLength);

			padPKCS7(transitentArray, dataLength);

			// Initialize AES cipher with the AES key
			aesCipherEnc.init(aesKey, Cipher.MODE_ENCRYPT);

			// Encrypt the data
			aesCipherEnc.doFinal(transitentArray, (short) 0, (short) (dataLength + paddingLength), transitentArray, (short) 0);

			return encryptedLength; // Return the length of encrypted data
		} catch (CryptoException e) {
			// Handle encryption error
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return 0x00; // Return null in case of error
		}
	}

	private void padPKCS7(byte[] data, short dataLength) {

		// Calculate the number of padding bytes needed
		short paddingLength = (short) (AES_KEY_SIZE_BYTES + (short) ((short)( - dataLength) % AES_KEY_SIZE_BYTES));

		// Add padding bytes
		//for (short i = (short) (data.length); i < (short) (data.length + paddingLength); i++) {
		//	paddedData[i] = (byte) paddingLength; // Set the padding byte value
		//}

		if (paddingLength > 0){
			Util.arrayFillNonAtomic(
					data,
					dataLength,
					paddingLength,
					(byte) paddingLength);
		}
	}


	private short getPKCS7PaddingLen(byte[] apduBuffer, short dataLength) {
		// Calculate the last byte, which represents the padding length
		short paddingLength = (short) (apduBuffer[dataLength] & 0xFF);

		// Ensure padding length is valid
		if (paddingLength <= (short) 0 || paddingLength > (short) 16) { // Assuming each block is 16 bytes
			// Padding is incorrect, throw exception or handle accordingly
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}

		// Calculate the length of the unpadded data
		return (short) (dataLength - paddingLength);
	}

	private void listSecrets(APDU apdu) {
		// Send response
		apdu.setOutgoing();
		//apdu.setOutgoingLength(MAX_SECRET_COUNT);

		//byte[] secretStatusCopy = new byte[MAX_SECRET_COUNT];
		//Util.arrayCopyNonAtomic(secretStatus, (short) 0, secretStatusCopy, (short) 0, MAX_SECRET_COUNT);
		short encryptedLength = encryptData(secretStatus, MAX_SECRET_COUNT); // Encrypt the data and get the modified array

		apdu.setOutgoingLength(encryptedLength); // Set outgoing length to the size of encrypted data

		apdu.sendBytesLong(transitentArray, (short) 0, encryptedLength);
	}

	public boolean select(boolean b) {
		deselect(true);
		return true;
	}

	public void deselect(boolean b) {

		//if (stateModel.getState() != StateModel.STATE_APPLET_UPLOADED) {
		//	stateModel.changeState(StateModel.STATE_UNPRIVILEGED);
		//}
		// clear key?
		aesKey.clearKey();
		rsaPublicKey.clearKey();
		Util.arrayFillNonAtomic(
				aesKeyEncrypted,
				(short) 0,
				(short) aesKeyEncrypted.length,
				(byte) 0x00);
		Util.arrayFillNonAtomic(
				rsaKeyBytes,
				(short) 0,
				(short) rsaKeyBytes.length,
				(byte) 0x00
		);
	}

	private void storeSecret(APDU apdu) {

		byte[] apduBuffer = apdu.getBuffer();

		decryptAPDU(apduBuffer);

		short dataLength = apduBuffer[ISO7816.OFFSET_LC];
		short index = apduBuffer[ISO7816.OFFSET_P1];
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

		short secretLength = (short) (dataLength - (short) PIN_LENGTH);

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

		byte[] secretValue = secretValues[queryKey].secretValue;
		short secretValueLen = secretValues[queryKey].getLength();

		if (secretValue == null) {
			// Handle the case where encryption failed
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short encryptedLength = encryptData(secretValue, secretValueLen);

		apdu.setOutgoing();
		apdu.setOutgoingLength(encryptedLength);
		apdu.sendBytesLong(transitentArray , (short) 0, encryptedLength);
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

		decryptAPDU(apduBuffer);

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
