package main.utils.constants;

public class InstructionConstants {
    // Instruction codes
    public static final short INS_SELECT = (short) 0xA4;
    public static final short INS_GET_DATA = (short) 0xB0;
    public static final short INS_SET_SECRET = (short) 0xC6;
    public static final short INS_REVEAL_SECRET = (short) 0x11;
    public static final short INS_GET_SECRET_NAMES = (short) 0xD7;
    public static final short INS_CHANGE_PIN = (short) 0xC2;
    public static final short INS_GET_STATE = (short) 0x1C;
    public static final short INS_VERIFY_PIN = (short) 0x1D;
    public static final short INS_INVALID = (short) 0x3C;
    public static final short INS_SC_INIT = (short) 0xE2;
    public static final byte INS_SC_GET_KEY = (byte) 0xD2;
}
