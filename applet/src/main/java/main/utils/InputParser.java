package main.utils;

import main.utils.constants.OffsetConstants;
import main.utils.enums.CardType;
import main.utils.enums.Instruction;

import java.io.Console;
import java.util.Collections;
import java.util.HashMap;

public class InputParser {
    private CardType cardType = CardType.REAL;
    private int terminalNumber = 0;

    private Instruction instruction = null;
    private String pin = null;
    private String newPin = null;
    private String keyName = null;
    private Byte keyIndex = null;
    private String value = null;
    private Byte overwrite = OffsetConstants.OVERWRITE_DONT;

    private static final int PIN_LENGTH = ApduFactory.PIN_LENGTH;
    private static final int SECRET_MAX_LENGTH = ApduFactory.SECRET_MAX_LENGTH;
    private static final int KEY_LENGTH = 255;

    /**
     * Parses command line arguments and initializes InputParser.
     * Initialized variables can be then accessed via getters.
     *
     * @param args Command line arguments
     */
    public void parseArgs (String[] args) {
        int i = 0;

        if (args.length == 0) {
            throw new IllegalArgumentException("No arguments provided");
        }

        if (args[0].equals("-h") || args[0].equals("--help")) {
            printHelp();
            cardType = CardType.HELP;
            return;
        }

        while (i < args.length) {
            switch (args[i]) {
                case "--sim":
                    cardType = CardType.SIMULATED;
                    i += 1;
                    break;
                case "-t":
                case "--terminal":
                    try {
                        terminalNumber = Integer.parseInt(args[i + 1]);
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("Invalid terminal number");
                    }
                    i += 2;
                    break;
                case "-i":
                case "--instruction":
                    instruction = resolveInstruction(args[i + 1]);
                    i += 2;
                    break;
                case "-p":
                case "--pin":
                    pin = sanitizePin(args[i + 1]);
                    i += 2;
                    break;
                case "-n":
                case "--new_pin":
                    newPin = sanitizePin(args[i + 1]);
                    i += 2;
                    break;
                case "-k":
                case "--key":
                    sanitizeAndSetKey(args[i + 1]);
                    i += 2;
                    break;
                case "-v":
                case "--value":
                    value = sanitizeValue(args[i + 1]);
                    i += 2;
                    break;
                case "-o":
                case "--overwrite":
                    overwrite = OffsetConstants.OVERWRITE_DO;
                    i += 1;
                    break;
                default:
                    i++;
                    break;
            }
        }

        testInputCombination();
    }

    /**
     * Prints help message.
     */
    public void printHelp() {
        System.out.println("-----SECRET STORAGE CARD CLIENT-----");
        System.out.println("Usage:");
        System.out.println("./gradlew run --args=\"[-h | --help] [-t <terminal number>] -i <instruction> [instruction_options]\"");
        System.out.println("java -jar applet-1.0-SNAPSHOT.jar [-h | --help] [-t <terminal number>] -i <instruction> [instruction_options]");
        System.out.println();
        System.out.println("Instruction options:");
        System.out.println("-p, --pin <pin>\tFour digit card PIN.");
        System.out.println("-n, --new_pin <pin>\tNew four digit PIN for PIN change.");
        System.out.printf("-k, --key <key>\tQuery data key. Should be a number 1-%d or the name of the slot.\n", KEY_LENGTH);
        System.out.println("-v, --value <value>\tQuery data value of length <= \n" + SECRET_MAX_LENGTH);
        System.out.println("-o, --overwrite\tOverwrite existing data on card.");
        System.out.println("--sim\t Run a card simulator. Default card type is real.");
        System.out.println();
        System.out.println("Instructions:");
        System.out.println("change_pin, cp\tPIN change.\tOptions: -p <old pin> -n <new pin>");
        System.out.println("get_secret_names, sn\tGet secret names.");
        System.out.println("reveal_secret, rs\tReveal secret.\tOptions: -p <pin> -k <key>");
        System.out.println("set_secret, set\tSet secret.\tOptions: -p <pin> -k <key> -v <value> [-o]");
    }

    /**
     * Resolves instruction to Instruction.
     *
     * @param instruction String version of Instruction
     * @return Instruction
     */
    private Instruction resolveInstruction(String instruction) {
        switch (instruction) {
            case "change_pin":
            case "cp":
                return Instruction.CHANGE_PIN;
            case "get_secret_names":
            case "sn":
                return Instruction.GET_SECRET_NAMES;
            case "reveal_secret":
            case "rs":
                return Instruction.REVEAL_SECRET;
            case "set_secret":
            case "set":
                return Instruction.SET_SECRET;
            default:
                printHelp();
                throw new IllegalArgumentException("Invalid instruction: " + instruction);
        }
    }


    /**
     * Checks if PIN is in correct form.
     *
     * @param pin PIN
     * @return Sanitized PIN
     */
    private String sanitizePin(String pin) {

        String trimmedPin = pin.trim();

        //Pin should only contain digits
        for (int i = 0; i < trimmedPin.length(); i++) {
            if (!Character.isDigit(trimmedPin.charAt(i))) {
                throw new IllegalArgumentException("Invalid PIN");
            }
        }

        //Pin should be exactly 4 digits
        if (trimmedPin.length() != PIN_LENGTH) {
            throw new IllegalArgumentException("Invalid PIN length");
        }

        return trimmedPin;
    }

    private String sanitizeValue(String value) {
        if (value.length() > SECRET_MAX_LENGTH) {
            throw new IllegalArgumentException("Value/secret is too long.");
        }

        return value;
    }

    /**
     * Checks if query key is in correct form.
     *
     * @param key Query key
     * @return Sanitized query key
     */
    private void sanitizeAndSetKey(String key) {

        String trimmedKey = key.trim();

        for (int i = 0; i < trimmedKey.length(); i++) {
            if (!Character.isDigit(trimmedKey.charAt(i))) {

                HashMap<Short, String> map = FileUtil.loadSecretNames();
                for (short i2 = (short) 0; i2 < map.size(); i2++) {
                    if (map.get(i2).equals(trimmedKey)) {
                        keyIndex = (byte) i2;
                        break;
                    }
                }

                keyName = trimmedKey;
                return;
            }
        }

       try {
           HashMap<Short, String> map = FileUtil.loadSecretNames();
           byte shortKey = Byte.parseByte(trimmedKey);

           if (map.containsKey((short) shortKey)) {
               keyName = map.get((short) shortKey);
               keyIndex = shortKey;
           } else {
               keyIndex = shortKey;
           }

       } catch (NumberFormatException e) {
           throw new IllegalArgumentException("Key is not of short type: " + key);
       }
    }

    /**
     * Tests input combinations of instructions.
     * Checks if all required parameters are set.
     */
    private void testInputCombination() {

        Console console = System.console();

        if (cardType == null) {
            throw new IllegalStateException("Card type is not set");
        }

        if (instruction == null) {
            throw new IllegalStateException("Instruction is not set");
        }

        switch (instruction) {
            case CHANGE_PIN:
                //Changing PIN requires old and new PIN
                if (pin == null) {
                    pin = sanitizePin(ConsoleWrapper.readPassword("Old PIN: "));
                }
                if (newPin == null) {
                    newPin = sanitizePin(ConsoleWrapper.readPassword("New PIN: "));
                }
                break;
            case GET_SECRET_NAMES:
                break;
            case REVEAL_SECRET:
                //Revealing secret requires PIN and key
                if (keyName == null && keyIndex == null) {
                    sanitizeAndSetKey(ConsoleWrapper.readLine("Key: "));
                }
                if (keyIndex == null) {
                    throw new IllegalArgumentException("Key index is not set or found");
                }
                if (pin == null) {
                    pin = sanitizePin(ConsoleWrapper.readPassword("PIN: "));
                }
                break;
            case SET_SECRET:
                //Setting secret requires PIN and key
                if (keyName == null && keyIndex == null) {
                    sanitizeAndSetKey(ConsoleWrapper.readLine("Key: "));
                }

                if (keyName == null) {
                    throw new IllegalArgumentException("Key name is not set");
                }

                if (keyIndex == null) {
                    HashMap<Short, String> map = FileUtil.loadSecretNames();

                    for (short i = (short) 0; i < map.size(); i++) {
                        if (map.get(i).equals(keyName)) {
                            keyIndex = (byte) i;
                            break;
                        }
                    }

                    if (keyIndex == null) {
                        keyIndex = (byte) (Collections.max(map.keySet()) + (short) 1);
                    }
                }

                if (value == null) {
                    value = sanitizeValue(ConsoleWrapper.readLine("Value: "));
                }
                if (pin == null) {
                    pin = sanitizePin(ConsoleWrapper.readPassword("PIN: "));
                }
                break;
            default:
                throw new IllegalStateException("Unknown instruction");
        }
    }

    public CardType getCardType() {
        return cardType;
    }

    public Instruction getInstruction() {
        return instruction;
    }

    public String getPin() {
        return pin;
    }

    public String getNewPin() {
        return newPin;
    }

    public String getKeyName() {
        return keyName;
    }

    public byte getKeyIndex() {
        return keyIndex;
    }

    public int getTerminalNumber() {
        return terminalNumber;
    }

    public String getValue() {
        return value;
    }

    public Byte getOverwrite() {
        return overwrite;
    }
}
