package main.utils;

import main.utils.constants.ClassConstants;
import main.utils.constants.InstructionConstants;
import main.utils.constants.OffsetConstants;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;

import static main.utils.ApduFactory.genericApdu;
import static org.junit.jupiter.api.Assertions.*;
public class ApduFactoryTest {

    @Test
    public void testPinChangeApdu() {
        CommandAPDU commandAPDU = ApduFactory.changePinApdu("1234", "4321", null);
        assertEquals(ClassConstants.CLA_BASIC, commandAPDU.getCLA());
        assertEquals(InstructionConstants.INS_CHANGE_PIN, commandAPDU.getINS());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP1());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP2());
        assertArrayEquals(TypeConverter.stringIntToByteArray("12344321"), commandAPDU.getData());
    }

    @Test
    public void testRevealSecretApdu() {
        CommandAPDU commandAPDU = ApduFactory.revealSecretApdu("1234", (byte) 0x01, null);
        assertEquals(ClassConstants.CLA_BASIC, commandAPDU.getCLA());
        assertEquals(InstructionConstants.INS_REVEAL_SECRET, commandAPDU.getINS());
        assertEquals(OffsetConstants.OFFSET_ONE, commandAPDU.getP1());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP2());
        assertArrayEquals(TypeConverter.stringIntToByteArray("1234"), commandAPDU.getData());
    }

    @Test
    public void testRevealSecretApdu2() {
        CommandAPDU commandAPDU = ApduFactory.revealSecretApdu("1234", (byte) 0x0c, null);
        assertEquals(ClassConstants.CLA_BASIC, commandAPDU.getCLA());
        assertEquals(InstructionConstants.INS_REVEAL_SECRET, commandAPDU.getINS());
        assertEquals(OffsetConstants.OFFSET_TWELVE, commandAPDU.getP1());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP2());
        assertArrayEquals(TypeConverter.stringIntToByteArray("1234"), commandAPDU.getData());
    }

    @Test
    public void testSelectApdu() {
        CommandAPDU commandAPDU = ApduFactory.selectAppletApdu("1234");
        assertEquals(ClassConstants.CLA_BASIC, commandAPDU.getCLA());
        assertEquals(InstructionConstants.INS_SELECT, commandAPDU.getINS());
        assertEquals(OffsetConstants.OFFSET_SELECT, commandAPDU.getP1());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP2());
        assertArrayEquals(TypeConverter.hexStringToByteArray("1234"), commandAPDU.getData());
    }

    @Test
    public void testGetListOfSecretsApdu() {
        CommandAPDU commandAPDU = ApduFactory.requestSecretNamesApdu();
        assertEquals(ClassConstants.CLA_BASIC, commandAPDU.getCLA());
        assertEquals(InstructionConstants.INS_GET_SECRET_NAMES, commandAPDU.getINS());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP1());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP2());
        assertArrayEquals(TypeConverter.hexStringToByteArray(""), commandAPDU.getData());
    }

    @Test
    public void testInvalidApdu() {
        CommandAPDU commandAPDU = genericApdu(
                ClassConstants.CLA_BASIC,
                InstructionConstants.INS_INVALID,
                OffsetConstants.OFFSET_NULL,
                OffsetConstants.OFFSET_NULL,
                new byte[0]);

        assertEquals(ClassConstants.CLA_BASIC, commandAPDU.getCLA());
        assertEquals(InstructionConstants.INS_INVALID, commandAPDU.getINS());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP1());
        assertEquals(OffsetConstants.OFFSET_NULL, commandAPDU.getP2());
        assertArrayEquals(TypeConverter.hexStringToByteArray(""), commandAPDU.getData());
    }

    @Test
    public void testInvalidApdu2() {
        CommandAPDU commandAPDU = genericApdu(0xbc, 0x81, 0x15, 0xa6, new byte[5]);
        assertArrayEquals(TypeConverter.stringIntToByteArray("00000"), commandAPDU.getData());
    }

}