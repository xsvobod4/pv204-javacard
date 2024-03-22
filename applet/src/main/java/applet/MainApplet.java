package applet;

import java.util.Arrays;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import javacard.framework.*;
import sun.security.provider.SHA;

public class MainApplet extends Applet implements MultiSelectable, ExtendedLength {
	/**
	 * TODO: fix state model (secondary state check) - teď zakomentován, protože neprošlo nic
	 *
	 * TODO: implement PIN (object ownerPIN), jeho ověření, změnu...
	 *
	 * TODO: better store of secrets
	 *
	 * TODO: ClientApp - lepší posílání APDUs apod
	 * */

	private static final byte INS_LIST_SECRETS = (byte) 0xD7;
	private static final byte INS_GET_SECRET_VALUE = (byte) 0x11;
	private static final byte INS_GET_STATE = (byte) 0x1C;
	static final byte INS_VERIFY_PIN = (byte) 0x1D;
	static final byte INS_CHANGE_PIN = (byte) 0xC2;
	private static final byte INS_SC_INIT = (byte) 0xE2;

	private static final short MAX_SECRET_COUNT = 16;
	private static final short MAX_SECRET_NAME_LENGTH = 20;
	static final short MAX_SECRET_VALUE_LENGTH = 20;

	public final byte SECRET_NOT_FILLED = (byte) 0xC4;
	public final byte SECRET_FILLED = (byte) 0x26;

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
	private AESKey aesKey;
	private Cipher rsaCipher;
	private static final short AES_KEY_SIZE_BITS = KeyBuilder.LENGTH_AES_256;
	private static final short RSA_MODULUS_LENGTH = 256; // Length of RSA modulus in bytes
	private static final short AES_KEY_SIZE_BYTES = 16; // AES key size in bytes
	private static RandomData cspRNG;


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
		storeSecret(
				(short) 0x01,
				new byte[]{'V', 'a', 'l', 'u', 'e', '1'}
		);
		storeSecret(
				(short) 0x07,
				new byte[]{'V', 'a', 'l', 'u', 'e', '2'}
		);
		storeSecret(
				(short) 0x0A,
				new byte[]{'V', 'a', 'l', 'u', 'e', '3'}
		);

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
		short dataLength = apdu.setIncomingAndReceive();

		byte ins = apduBuffer[ISO7816.OFFSET_INS];

		switch (ins) {
			case INS_SC_INIT:
				// stateModel.checkAllowedFunction(StateModel.FNC_InitSecureChannel);
				initSecureChannel(apdu);
				break;
			case INS_LIST_SECRETS:
				// Check if the function is allowed in the current state
				stateModel.checkAllowedFunction(StateModel.FNC_lookupSecretNames);
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

	private void initSecureChannel(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();

		// Check if incoming data length is correct (should be the size of RSA modulus)
		if (dataLength != RSA_MODULUS_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Get the RSA public key modulus from the APDU buffer
		RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, RSA_MODULUS_LENGTH, false);
		rsaPublicKey.setModulus(apduBuffer, ISO7816.OFFSET_CDATA, dataLength);

		// Generate AES key
		byte[] aesKeyBytes = new byte[AES_KEY_SIZE_BYTES];
		doGenerateRandom(aesKeyBytes, (short) 0, AES_KEY_SIZE_BYTES);
		aesKey.setKey(aesKeyBytes, (short) 0);

		// Encrypt AES key using RSA public key
		rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
		short cipherLength = rsaCipher.doFinal(aesKeyBytes, (short) 0, AES_KEY_SIZE_BYTES, apduBuffer, (short) 0);

		// Send encrypted AES key as response
		apdu.setOutgoing();
		apdu.setOutgoingLength(cipherLength);
		apdu.sendBytesLong(apduBuffer, (short) 0, cipherLength);
	}


	static void doGenerateRandom(byte[] buffer, short offset, short length) {
		cspRNG.generateData(buffer, offset, length);
	}

	private void listSecrets(APDU apdu) {
		// Send response
		apdu.setOutgoing();
		apdu.setOutgoingLength(MAX_SECRET_COUNT);
		apdu.sendBytesLong(secretStatus, (short) 0, MAX_SECRET_COUNT);
	}

	public boolean select(boolean b) {
		return true;
	}

	public void deselect(boolean b) {

		if (stateModel.getState() != StateModel.STATE_APPLET_UPLOADED) {
			stateModel.changeState(StateModel.STATE_UNPRIVILEGED);
		}

	}

	//TODO: Add value to the SecretStore array and set the secret (at the same index) to filled status
	private void storeSecret(short index, byte[] value) {

		// Check if the store is full
		if (secretCount >= MAX_SECRET_COUNT) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}

		// Check if the index is out of range
		if (index >= MAX_SECRET_COUNT) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Check if index is a negative number
		if (index < 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		short valueLength = (short) value.length;

		// Check if the value being stored is too long
		if (valueLength > MAX_SECRET_VALUE_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Store the value
		Util.arrayCopyNonAtomic(value, (short) 0, secretValues[index].secretValue, (short) 0, valueLength);
		secretValues[index].setLength(valueLength);
		secretStatus[index] = SECRET_FILLED;
		secretCount++;
	}

	private void getSecretValue(APDU apdu) {

		// Verify PIN
		if (verifyPIN(apdu, ISO7816.OFFSET_CDATA, (short) 9) != RTR_PIN_SUCCESS) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		byte[] apduBuffer = apdu.getBuffer();
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

		short secretLength = secretValues[queryKey].getLength();

		apdu.setOutgoing();
		apdu.setOutgoingLength(secretLength);
		apdu.sendBytesLong(secretValues[queryKey].secretValue, (short) 0, secretLength);
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

		stateModel.changeState(StateModel.STATE_PRIVILEGED);
		pin.update(apduBuffer, PIN_DEFAULT_OFFSETS[2], PIN_LENGTH);

//		stateModel.changeState(StateModel.STATE_UNPRIVILEGED);
		ISOException.throwIt(ISO7816.SW_NO_ERROR);
	}
}
