package main.utils;

import main.exceptions.DataLengthException;
import main.utils.constants.ClassConstants;
import main.utils.constants.InstructionConstants;
import main.utils.constants.OffsetConstants;

import javax.smartcardio.CommandAPDU;

public class ApduFactory {

    private static final short KEY_MAX_VALUE = (short) 15;
    private static final short PIN_MAX_LENGTH = (short) 4;
    private static final short SECRET_MAX_VALUE = (short) 240;

    private static CommandAPDU genericApdu(int cla, int ins, int p1, int p2, byte[] data) {
        return new CommandAPDU(cla, ins, p1, p2, data);
    }

    public static CommandAPDU sendPinApdu(String pin) {

        if (pin.length() > PIN_MAX_LENGTH) {
            throw new DataLengthException("Pin is of incorrect length");
        }

        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_CHANGE_PIN,
                OffsetConstants.OFFSET_NULL,
                OffsetConstants.OFFSET_NULL,
                TypeConverter.hexStringToByteArray(pin));
    }

    public static CommandAPDU requestSecretNamesApdu() {
        return genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_GET_SECRET_NAMES,
                OffsetConstants.OFFSET_NULL,
                OffsetConstants.OFFSET_NULL,
                new byte[0]);
    }
}
