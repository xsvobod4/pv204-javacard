package main.utils;

import main.utils.constants.OffsetConstants;
import main.utils.enums.CardType;
import main.utils.enums.Instruction;

import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

public class InputParserTest {

    @Test
    public void testCorrectRealCard() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-t", "1", "-i", "get_secret_names"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(1, inputParser.getTerminalNumber());
        assertEquals(Instruction.GET_SECRET_NAMES, inputParser.getInstruction());
    }

    @Test
    public void testCorrectRealCard2() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "get_secret_names"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(0, inputParser.getTerminalNumber());
        assertEquals(Instruction.GET_SECRET_NAMES, inputParser.getInstruction());
    }

    @Test
    public void testCorrectSimulatedCard() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"--sim", "-i", "get_secret_names"});
        assertEquals(CardType.SIMULATED, inputParser.getCardType());
        assertEquals(Instruction.GET_SECRET_NAMES, inputParser.getInstruction());
    }

    @Test
    public void testCorrectChangePin() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "change_pin", "-p", "1234", "-n", "4321", "--sim"});
        assertEquals(CardType.SIMULATED, inputParser.getCardType());
        assertEquals(Instruction.CHANGE_PIN, inputParser.getInstruction());
        assertEquals("1234", inputParser.getPin());
        assertEquals("4321", inputParser.getNewPin());
    }

    @Test
    public void testCorrectChangePin2() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "change_pin", "-n", "4321", "-p", "5678"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(Instruction.CHANGE_PIN, inputParser.getInstruction());
        assertEquals("5678", inputParser.getPin());
        assertEquals("4321", inputParser.getNewPin());
    }

    @Test
    public void testPinTooLong() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "change_pin", "-n", "4321802850", "-p", "5678443"});
        });
    }

    @Test
    public void testCorrectRevealSecret() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"--sim", "-i", "reveal_secret", "-p", "1234", "-k", "1"});
        assertEquals(CardType.SIMULATED, inputParser.getCardType());
        assertEquals(Instruction.REVEAL_SECRET, inputParser.getInstruction());
        assertEquals("1234", inputParser.getPin());
        assertEquals((byte) 0x01, inputParser.getKeyIndex());
    }

    @Test
    public void testCorrectRevealSecret2() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-k", "1", "-p", "1234"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(Instruction.REVEAL_SECRET, inputParser.getInstruction());
        assertEquals("1234", inputParser.getPin());
        assertEquals((byte) 0x01, inputParser.getKeyIndex());
    }

    @Test
    public void testWrongKeyLookup() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-k", "AS445cDIFU", "-p", "1234"});
        });
    }

    @Test
    public void testOutOfBoundsKey() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-k", "16", "-p", "1234"});
        });
    }

    @Test
    public void testCustomKey() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-k", "Office365", "-p", "1234"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(Instruction.REVEAL_SECRET, inputParser.getInstruction());
        assertEquals("1234", inputParser.getPin());
        assertEquals((byte) 0x01, inputParser.getKeyIndex());
        assertEquals("Office365", inputParser.getKeyName());
    }

    @Test
    public void testCustomKeyNotInList() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-k", "nfiqruiir888", "-p", "1234"});
        });
    }

    @Test
    public void testIllegalKey() {
        InputParser inputParser = new InputParser();
        assertThrows(NullPointerException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "set", "-k", "GOOGLE\noifjsiro", "-p", "1234"});
        });
    }

    @Test
    public void testIllegalKey2() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-k", "asdfmm,oifj,siro", "-p", "1234"});
        });
    }

    @Test
    public void testCorrectListSecrets() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "get_secret_names"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(Instruction.GET_SECRET_NAMES, inputParser.getInstruction());
    }

    @Test
    public void testNonsensicalInput() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalStateException.class, () -> {
            inputParser.parseArgs(new String[]{"get_secret_names", "fmlksffjfopjfda", "dsd", "1233341", "-gggga"});
        });
    }

    @Test
    public void testEmptyInput() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{});
        });
    }

    @Test
    public void testWrongInstruction() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "fmlksffjfopjfda"});
        });
    }

    @Test
    public void testChangePinNoPin() {
        InputParser inputParser = new InputParser();

        assertThrows(NullPointerException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "change_pin", "--sim", "-n", "4321"});
        });
    }

    @Test
    public void testChangePinNoNewPin() {
        InputParser inputParser = new InputParser();
        assertThrows(NullPointerException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "change_pin", "-p", "1234"});
        });
    }

    @Test
    public void testRevealSecretNoPin() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"--sim", "-i", "reveal_secret", "-k", "11"});
        });
    }

    @Test
    public void testRevealSecretNoKey() {
        InputParser inputParser = new InputParser();
        assertThrows(NullPointerException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-p", "1234"});
        });
    }

    @Test
    public void testInvalidPin() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-p", "1234834098503453", "-k", "11"});
        });
    }

    @Test
    public void testInvalidPin2() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-p", "123c", "-k", "11"});
        });
    }

    @Test
    public void testInvalidKey() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "reveal_secret", "-p", "1234", "-k", "490000333"});
        });
    }

    @Test
    public void testCorrectSetSecret() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "set_secret", "-v", "1234ddcc@g", "-p", "1234", "-k", "0"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(Instruction.SET_SECRET, inputParser.getInstruction());
        assertEquals("1234ddcc@g", inputParser.getValue());
        assertEquals("1234", inputParser.getPin());
        assertEquals(OffsetConstants.OVERWRITE_DONT, inputParser.getOverwrite().byteValue());
    }

    @Test
    public void testCorrectSetSecret2() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"--sim", "-i", "set", "-v", "123n9c18989r``/c_", "-k", "2", "-p", "1234", "-o"});
        assertEquals(CardType.SIMULATED, inputParser.getCardType());
        assertEquals(Instruction.SET_SECRET, inputParser.getInstruction());
        assertEquals("123n9c18989r``/c_", inputParser.getValue());
        assertEquals("1234", inputParser.getPin());
        assertEquals(OffsetConstants.OVERWRITE_DO, inputParser.getOverwrite().byteValue());
    }

    @Test
    public void testIncorrectSetSecret() {
        InputParser inputParser = new InputParser();
        assertThrows(NullPointerException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "set_secret", "-v", "123n9c18989r``/c_"});
        });
    }

    @Test
    public void testIncorrectSetSecret2() {
        InputParser inputParser = new InputParser();
        assertThrows(NullPointerException.class, () -> {
            inputParser.parseArgs(new String[]{"-i", "set_secret", "-v", "123n9c18989r``/c_", "--overwrite", "-k", "0"});
        });
    }

    @Test
    public void testIncorrectSetSecret3() {
        InputParser inputParser = new InputParser();
        assertThrows(NullPointerException.class, () -> {
            inputParser.parseArgs(new String[]{"--sim", "-i", "set", "-p", "1234", "-o"});
        });
    }

    @Test
    public void testIncorrectSetSecret4() {
        InputParser inputParser = new InputParser();
        assertThrows(IllegalArgumentException.class, () -> {
            inputParser.parseArgs(new String[]{"--sim", "-i", "set", "-p", "1234", "-o", "-k", "99999", "-v", "123n9c18989r.../c_"});
        });
    }

    @Test
    public void testSetSecretCustomKey() {
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(new String[]{"-i", "set_secret", "-v", "123n9c18989r``/c_", "-k", "GOOGLE", "-p", "1234", "-o"});
        assertEquals(CardType.REAL, inputParser.getCardType());
        assertEquals(Instruction.SET_SECRET, inputParser.getInstruction());
        assertEquals("123n9c18989r``/c_", inputParser.getValue());
        assertEquals("1234", inputParser.getPin());
        assertEquals(OffsetConstants.OVERWRITE_DO, inputParser.getOverwrite().byteValue());
    }
}