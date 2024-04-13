package main.cardinterface;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import main.exceptions.*;
import main.security.JcSecureChannel;
import main.utils.ApduFactory;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.nio.charset.StandardCharsets;

public class SimulatedCard implements ICard {

    private final CardSimulator simulator;
    private AID appletAID;
    private JcSecureChannel secureChannel;

    /**
     * Constructor of SimulatedCard.
     * Prepares the applet AID and the simulator.
     *
     * @param aid Applet AID
     */
    public SimulatedCard(String aid) {
        appletAID = AIDUtil.create(aid);
        simulator = new CardSimulator();
        simulator.installApplet(appletAID, MainApplet.class);
        //simulator.selectApplet(appletAID);

        secureChannel = new JcSecureChannel();
        secureChannel.setUpScSim(simulator, appletAID);
    }

    @Override
    public void sendPin(String pin) {
        CommandAPDU commandAPDU = ApduFactory.sendPinApdu(pin);
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

        if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Failed to send pin. Card code: " + responseAPDU.getSW());
        }
    }

    @Override
    public void storeValue(Byte key, String value, String pin, Byte overwrite) {
        CommandAPDU commandAPDU = ApduFactory.setSecretApdu(key, overwrite, value, pin, secureChannel);
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

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
            throw new CardRuntimeException("Failed to store value. Card code: " + responseAPDU.getSW());
        }
    }

    @Override
    public byte[] getSecretNames() {

        CommandAPDU commandAPDU = ApduFactory.requestSecretNamesApdu();
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

        if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Failed to get secret names. Card code: " + responseAPDU.getSW());
        }

        return secureChannel.decrypt(responseAPDU.getData());
    }

    @Override
    public String revealSecret(String pin, Byte key) {

        if (pin.length() != ApduFactory.PIN_LENGTH) {
            throw new DataLengthException("PIN of wrong size.");
        }

        CommandAPDU commandAPDU = ApduFactory.revealSecretApdu(pin, key, secureChannel);
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

        if ((short) responseAPDU.getSW() == ISO7816.SW_DATA_INVALID) {
            throw new SecretIndexException("No secret at this key/index.");
        }

        if ((short) responseAPDU.getSW() == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) {
            throw new WrongPinException("Wrong PIN.");
        }

        if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Failed to get secret. Card code: " + responseAPDU.getSW());
        }

        byte[] decryptedData = secureChannel.decrypt(responseAPDU.getData());

        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    @Override
    public void changePin(String oldPin, String newPin) {

        if (oldPin.length() != ApduFactory.PIN_LENGTH) {
            throw new DataLengthException("Old PIN of wrong size.");
        }

        if (newPin.length() != ApduFactory.PIN_LENGTH) {
            throw new DataLengthException("New PIN of wrong size.");
        }

        CommandAPDU commandAPDU = ApduFactory.changePinApdu(oldPin, newPin, secureChannel);
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

        if ((short) responseAPDU.getSW() == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) {
            throw new WrongPinException("Wrong PIN.");
        }

        if ((short) responseAPDU.getSW() > (short) 0) {
            throw new CardRuntimeException("Failed to change pin. Card code: " + (short) responseAPDU.getSW());
        }
    }
}
