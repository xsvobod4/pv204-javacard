package main.cardinterface;

import javacard.framework.ISO7816;
import main.exceptions.*;
import main.utils.ApduFactory;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.smartcardio.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class RealCard implements ICard {

    private Card card;
    private CardChannel channel;
    private String aid;

    /**
     * RealCard constructor.
     * Connects to the card and holds a channel.
     *
     * @param aid Applet AID
     * @param cardNumber Terminal number
     * @throws CardException Failed to connect to the card. Probably wrong terminal number.
     */
    public RealCard(String aid, int cardNumber) throws CardException {
        TerminalFactory tf = TerminalFactory.getDefault();
        List<CardTerminal> terminals = tf.terminals().list();
        CardTerminal terminal = terminals.get(cardNumber);
        card = terminal.connect("*");
        channel = card.getBasicChannel();
        this.aid = aid;
    }


    @Override
    public void sendPin(String pin) {

        try {
            select();
            CommandAPDU commandAPDU = ApduFactory.sendPinApdu(pin);
            ResponseAPDU responseAPDU = channel.transmit(commandAPDU);

            if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
                throw new CardRuntimeException("Failed to send pin. Card code: " + responseAPDU.getSW());
            }

        } catch (CardException e) {
            throw new CardRuntimeException("Card connection problem. Failed to send pin. Card code: " + e.getMessage());
        }
    }

    @Override
    public void storeValue(Byte key, String value, String pin, Byte overwrite) {
        try {
            select();
            CommandAPDU commandAPDU = ApduFactory.setSecretApdu(key, overwrite, value, pin);
            ResponseAPDU responseAPDU = channel.transmit(commandAPDU);

            if ((short) responseAPDU.getSW() == ISO7816.SW_WRONG_LENGTH) {
                throw new DataLengthException("Value is too long.");
            }

            if ((short) responseAPDU.getSW() == ISO7816.SW_CONDITIONS_NOT_SATISFIED) {
                throw new OverwriteException("Secrect would be overwritten.");
            }

            if ((short) responseAPDU.getSW() == ISO7816.SW_INCORRECT_P1P2) {
                throw new SecretIndexException("Secret index is out of bounds.");
            }

            if ((short) responseAPDU.getSW() == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) {
                throw new WrongPinException("Wrong PIN.");
            }

            if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
                throw new CardRuntimeException("Failed to send pin. Card code: " + responseAPDU.getSW());
            }
        } catch (CardException e) {
            throw new CardRuntimeException("Card connection problem. Failed to store value. Card code: " + e.getMessage());
        }

    }

    @Override
    public byte[] getSecretNames() {

        try {
            select();
            CommandAPDU commandAPDU = ApduFactory.requestSecretNamesApdu();
            ResponseAPDU responseAPDU = channel.transmit(commandAPDU);

            if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
                throw new CardRuntimeException("Failed to get secret names. Card code: " + responseAPDU.getSW());
            }

            return responseAPDU.getData();
        } catch (CardException e) {
            throw new CardRuntimeException("Card connection problem. Failed to get secret names. Card code: " + e.getMessage());
        }
    }

    @Override
    public String revealSecret(String pin, Byte key) {

        if (pin.length() != ApduFactory.PIN_LENGTH) {
            throw new DataLengthException("PIN of wrong size.");
        }

        try {
            select();
            CommandAPDU commandAPDU = ApduFactory.revealSecretApdu(pin, key);
            ResponseAPDU responseAPDU = channel.transmit(commandAPDU);

            if ((short) responseAPDU.getSW() == ISO7816.SW_DATA_INVALID) {
                throw new SecretIndexException("No secret at this key/index.");
            }

            if ((short) responseAPDU.getSW() == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) {
                throw new WrongPinException("Wrong PIN.");
            }

            if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
                throw new CardRuntimeException("Failed to get secret. Card code: " + responseAPDU.getSW());
            }

            return new String(responseAPDU.getData(), StandardCharsets.UTF_8);
        } catch (CardException e) {
            throw new CardRuntimeException("Card connection problem. Failed to reveal secret. Card code: " + e.getMessage());
        }
    }

    @Override
    public void changePin(String oldPin, String newPin) {

        if (oldPin.length() != ApduFactory.PIN_LENGTH) {
            throw new DataLengthException("Old PIN of wrong size.");
        }

        if (newPin.length() != ApduFactory.PIN_LENGTH) {
            throw new DataLengthException("New PIN of wrong size.");
        }

        try {
            select();
            CommandAPDU commandAPDU = ApduFactory.changePinApdu(oldPin, newPin);
            ResponseAPDU responseAPDU = channel.transmit(commandAPDU);

            if ((short) responseAPDU.getSW() == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) {
                throw new WrongPinException("Wrong PIN.");
            }

            if ((short) responseAPDU.getSW() > (short) 0) {
                throw new CardRuntimeException("Failed to change pin. Card code: " + (short) responseAPDU.getSW());
            }

        } catch (CardException e) {
            throw new CardRuntimeException("Card connection problem. Failed to change pin. Card code: " + e.getMessage());
        }
    }

    /**
     * Selects the applet.
     *
     * @throws CardException Failed to select the applet
     */
    private void select() throws CardException {

        CommandAPDU commandAPDU = ApduFactory.selectAppletApdu(aid);
        ResponseAPDU responseAPDU = channel.transmit(commandAPDU);

        if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Failed to select applet. Card code: " + (short) responseAPDU.getSW());
        }
    }
}
