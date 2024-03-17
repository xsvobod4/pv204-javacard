package main.utils;

import main.utils.enums.CardType;
import main.utils.enums.Instruction;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class InputParser {
    private CardType cardType = null;
    private int terminalNumber = 0;

    private Instruction instruction = null;
    private String pin = null;
    private String newPin = null;
    private String key = null;

    private static final int PIN_LENGTH = ApduFactory.PIN_LENGTH;
    private static final int KEY_LENGTH = 7;

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
            return;
        }

        while (i < args.length-1) {
            switch (args[i]) {
                case "-c":
                case "--card":
                    cardType = resolveCardType(args[i + 1]);
                    i += 2;
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
                    key = sanitizeKey(args[i + 1]);
                    i += 2;
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
        System.out.println("java -jar client.jar [-h | --help] -c <card type> [-t <terminal number>] -i <instruction> [instruction_options]");
        System.out.println("./gradlew run --args=\"[-h | --help] -c <card type> [-t <terminal number>] -i <instruction> [instruction_options]\"");
        System.out.println();
        System.out.println("Instruction options:");
        System.out.println("-p, --pin <pin>\t\tFour digit card PIN.");
        System.out.println("-n, --new_pin <pin>\tNew four digit PIN for PIN change.");
        System.out.printf("-k, --key <key>\t\tQuery data key. Should be at most %d character long keyword.\n", KEY_LENGTH);
        System.out.println();
        System.out.println("Card types:");
        System.out.println("sim\tSimulated card.");
        System.out.println("real\tReal card.");
        System.out.println();
        System.out.println("Instructions:");
        System.out.println("change_pin, cp\t\tPIN change.\tOptions: -p <old pin> -n <new pin>");
        System.out.println("get_secret_names, sn\tGet secret names.");
        System.out.println("reveal_secret, rs\tReveal secret.\tOptions: -p <pin> -k <key>");
    }

    /**
     * Assigns CardType to cardType.
     *
     * @param cardType String version of CardType
     * @return CardType
     */
    private CardType resolveCardType(String cardType) {
        switch (cardType) {
            case "sim":
            case "simulated":
                return CardType.SIMULATED;
            case "real":
                return CardType.REAL;
            default:
                printHelp();
                throw new IllegalArgumentException("Invalid card type: " + cardType);
        }
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
                throw new IllegalArgumentException("Invalid PIN: " + pin);
            }
        }

        //Pin should be exactly 4 digits
        if (trimmedPin.length() != PIN_LENGTH) {
            throw new IllegalArgumentException("Invalid PIN length: " + pin.length());
        }

        return trimmedPin;
    }

    /**
     * Checks if query key is in correct form.
     *
     * @param key Query key
     * @return Sanitized query key
     */
    private String sanitizeKey(String key) {

        String trimmedKey = key.trim();

        //Only printable characters can be a key
        if (!isPrintable(trimmedKey)) {
            throw new IllegalArgumentException("Key should only feature printable characters: ");
        }

        try {
            //Key is a string of length at most KEY_LENGTH
            if (key.length() > KEY_LENGTH) {
                throw new IllegalArgumentException("Key too long: ");
            } else if (key.length() < KEY_LENGTH) {
                //Key is padded up to the value of KEY_LENGTH with spaces
                trimmedKey = trimmedKey +
                        new String(new char[KEY_LENGTH - trimmedKey.length()]).replace('\0', ' ');
            }
        } catch (NumberFormatException e) {
            printHelp();
            throw new IllegalArgumentException("Invalid key: " + trimmedKey);
        }

        return trimmedKey;
    }

    /**
     * Tests input combinations of instructions.
     * Checks if all required parameters are set.
     */
    private void testInputCombination() {

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
                    throw new IllegalStateException("Old PIN is not set");
                }
                if (newPin == null) {
                    throw new IllegalStateException("New PIN is not set");
                }
                break;
            case GET_SECRET_NAMES:
                break;
            case REVEAL_SECRET:
                //Revealing secret requires PIN and key
                if (pin == null) {
                    throw new IllegalStateException("PIN is not set");
                }
                if (key == null) {
                    throw new IllegalStateException("Key is not set");
                }
                break;
            default:
                throw new IllegalStateException("Unknown instruction");
        }
    }

    private boolean isPrintable(String str) {
        return str.chars().allMatch(c -> c >= 33 && c <= 126);
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

    public String getKey() {
        return key;
    }

    public int getTerminalNumber() {
        return terminalNumber;
    }
}
