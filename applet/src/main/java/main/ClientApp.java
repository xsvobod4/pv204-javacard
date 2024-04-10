package main;

import main.cardinterface.ICard;
import main.cardinterface.RealCard;
import main.cardinterface.SimulatedCard;
import main.exceptions.SecretIndexException;
import main.utils.FileUtil;
import main.utils.InputParser;
import main.utils.constants.CardSettings;
import main.utils.constants.ReturnMsgConstants;
import main.utils.enums.CardType;

import javax.smartcardio.CardException;
import java.util.HashMap;

public class ClientApp {


    public static void main(String[] args){

        //Can be either simulated or real
        ICard card;

        //Parses the CLI inputs
        //Help and usage is described in InputParser
        //Is also responsible for sanitization
        InputParser inputParser = new InputParser();
        inputParser.parseArgs(args);

        //Decide the card type
        if (inputParser.getCardType() == CardType.SIMULATED) {
            card = new SimulatedCard(CardSettings.AID);
        } else if (inputParser.getCardType() == CardType.REAL) {
            try {
                //Real card. We assume the terminal might not be connected here
                //or the terminal number points to a wrong terminal - exception thrown.
                card = new RealCard(CardSettings.AID, inputParser.getTerminalNumber());
            } catch (CardException e) {
                throw new RuntimeException("Failed to connect to the card. Try different terminal: " + e.getMessage());
            }
        } else {
           return;
        }

        //Execute the instruction
        switch (inputParser.getInstruction()) {
            case CHANGE_PIN:
                card.changePin(inputParser.getPin(), inputParser.getNewPin());
                break;
            case GET_SECRET_NAMES:
                getSecretNames(card);
                break;
            case REVEAL_SECRET:
                revealSecret(inputParser.getPin(), inputParser.getKeyIndex(), card);
                break;
            case SET_SECRET:
                setSecret(inputParser, card);
                break;
            default:
                throw new IllegalArgumentException("Invalid instruction: " + inputParser.getInstruction());
        }
    }

    private static void revealSecret(String pin, Byte key, ICard card) {
        try {
            String secret = card.revealSecret(pin, key);
            //Simply prints the secret onto the screen. Can be used for piping.
            System.out.println(secret);
        } catch (SecretIndexException e) {
            System.out.println("Secret not found at this key/index");
        }
    }

    private static void getSecretNames(ICard card) {
        byte[] secretNames = card.getSecretNames();
        HashMap<Short, String> nameMapper = FileUtil.loadSecretNames();

        //Simply prints the secret names onto the screen. Can be used for piping.
        for (short i = (short) 0; i < secretNames.length; i++) {
            if (secretNames[i] == ReturnMsgConstants.SECRET_FILLED) {
                System.out.println(i + "\t" + nameMapper.getOrDefault(i, "Unknown"));
            }
        }
    }

    private static void setSecret(InputParser inputParser, ICard card) {

        card.storeValue(inputParser.getKeyIndex(),
                inputParser.getValue(),
                inputParser.getPin(),
                inputParser.getOverwrite());

        boolean writeIntoFile = false;
        byte[] secretNames = card.getSecretNames();
        HashMap<Short, String> nameMapper = FileUtil.loadSecretNames();

        if (secretNames[inputParser.getKeyIndex()] != ReturnMsgConstants.SECRET_FILLED) {
            throw new IllegalStateException("Secret name was not correctly saved.");
        }

        if (!nameMapper.containsKey((short)inputParser.getKeyIndex())) {
            writeIntoFile = true;
        }

        if (writeIntoFile) {
            FileUtil.saveSecretPair(inputParser.getKeyIndex(),
                    inputParser.getKeyName());
        }
    }
}


