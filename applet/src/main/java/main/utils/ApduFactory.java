package main.utils;

import javacard.framework.ISO7816;
import javacard.framework.Util;
import main.exceptions.CardRuntimeException;
import main.exceptions.DataLengthException;
import main.utils.constants.ClassConstants;
import main.utils.constants.InstructionConstants;
import main.utils.constants.OffsetConstants;

import javax.smartcardio.CommandAPDU;

public class ApduFactory {

    public static final short KEY_LENGTH = (short) 15;
    public static final short PIN_LENGTH = (short) 4;
    public static final short SECRET_MAX_LENGTH = (short) 64;

    /**
     * Builds APDU
     *
     * @param cla APDU class
     * @param ins APDU instruction
     * @param p1 APDU parameter 1
     * @param p2 APDU parameter 2
     * @param data APDU data
     * @return Built APDU
     */
    //TODO: Make private
    public static CommandAPDU genericApdu(int cla, int ins, int p1, int p2, byte[] data) {
        return new CommandAPDU(cla, ins, p1, p2, data);
    }

    /**
     * Creates APDU to send PIN
     *
     * @param pin PIN
     * @return Built APDU
     */
    public static CommandAPDU sendPinApdu(String pin) {

        if (pin.length() != PIN_LENGTH) {
            throw new DataLengthException("Pin is of incorrect length");
        }

        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_CHANGE_PIN,
                OffsetConstants.OFFSET_NULL,
                OffsetConstants.OFFSET_NULL,
                TypeConverter.stringIntToByteArray(pin));
    }

    /**
     * Creates an APDU for listing secret names
     *
     * @return Built APDU
     */
    public static CommandAPDU requestSecretNamesApdu() {
        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_GET_SECRET_NAMES,
                OffsetConstants.OFFSET_NULL,
                OffsetConstants.OFFSET_NULL,
                new byte[0]);
    }

    /**
     * Builds APDU for revealing secrets from the card by key.
     *
     * @param pin PIN
     * @param key Key
     * @return Built APDU
     */
    public static CommandAPDU revealSecretApdu(String pin, Byte key) {

        if (pin.length() != PIN_LENGTH) {
            throw new DataLengthException("Pin is of incorrect length");
        }

        if ((short) key > KEY_LENGTH || (short) key < (short) 0) {
            throw new DataLengthException("Data key is of incorrect length");
        }

        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_REVEAL_SECRET,
                key,
                OffsetConstants.OFFSET_NULL,
                TypeConverter.stringIntToByteArray(pin));
    }

    /**
     * Creates an APDU for changing PIN
     *
     * @param oldPin Old PIN
     * @param newPin New PIN
     * @return Built APDU
     */
    public static CommandAPDU changePinApdu(String oldPin, String newPin) {

        if (oldPin.length() != PIN_LENGTH) {
            throw new DataLengthException("Old pin is of incorrect length");
        }

        if (newPin.length() != PIN_LENGTH) {
            throw new DataLengthException("New pin is of incorrect length");
        }

        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_CHANGE_PIN,
                OffsetConstants.OFFSET_NULL,
                OffsetConstants.OFFSET_NULL,
                TypeConverter.stringIntToByteArray(oldPin+newPin));
    }

    public static CommandAPDU setSecretApdu(Byte key, Byte overwrite, String secret, String pin) {

        if (secret.length() > SECRET_MAX_LENGTH) {
            throw new DataLengthException("Secret is of incorrect length");
        }

        if (pin.length() != PIN_LENGTH) {
            throw new DataLengthException("Pin is of incorrect length");
        }

        if (overwrite != OffsetConstants.OVERWRITE_DO && overwrite != OffsetConstants.OVERWRITE_DONT) {
            throw new CardRuntimeException("Overwrite is of incorrect value");
        }

        byte[] combined = new byte[secret.length() + PIN_LENGTH];

        Util.arrayCopyNonAtomic(TypeConverter.stringIntToByteArray(pin),
                (short) 0,
                combined,
                (short) 0,
                PIN_LENGTH);

        Util.arrayCopyNonAtomic(secret.getBytes(),
                (short) 0,
                combined,
                PIN_LENGTH,
                (short) secret.length());

        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_SET_SECRET,
                key,
                overwrite,
                combined);
    }

    /**
     * Creates APDU for selecting an applet. Used in real cards.
     *
     * @param appletAID Applet AID
     * @return Built APDU
     */
    public static CommandAPDU selectAppletApdu(String appletAID) {
        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_SELECT,
                OffsetConstants.OFFSET_SELECT,
                OffsetConstants.OFFSET_NULL,
                TypeConverter.hexStringToByteArray(appletAID));
    }
}
