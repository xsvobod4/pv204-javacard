package main;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import main.cardinterface.ICard;
import main.cardinterface.RealCard;
import main.cardinterface.SimulatedCard;
import main.utils.InputParser;
import main.utils.constants.CardSettings;
import main.utils.enums.CardType;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import java.util.ArrayList;

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
            throw new IllegalArgumentException("Invalid card type: " + inputParser.getCardType());
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
                revealSecret(inputParser.getPin(), inputParser.getKey(), card);
                break;
            default:
                throw new IllegalArgumentException("Invalid instruction: " + inputParser.getInstruction());
        }
    }

    private static void revealSecret(String pin, String key, ICard card) {
        String secret = card.revealSecret(pin, key);
        //Simply prints the secret onto the screen. Can be used for piping.
        System.out.println(secret);
    }

    private static void getSecretNames(ICard card) {
        ArrayList<String> secretNames = card.getSecretNames();
        //Simply prints the secret names onto the screen. Can be used for piping.
        for (String secretName : secretNames) {
            System.out.println(secretName);
        }
    }
}
