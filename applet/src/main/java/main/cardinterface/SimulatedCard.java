package main.cardinterface;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import main.exceptions.CardRuntimeException;
import main.utils.ApduFactory;
import main.utils.DataFormatProcessor;
import main.utils.constants.ReturnMsgConstants;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;

public class SimulatedCard implements ICard {

    private final CardSimulator simulator;
    private AID appletAID;

    public SimulatedCard(String aid) {
        appletAID = AIDUtil.create(aid);
        simulator = new CardSimulator();
        simulator.installApplet(appletAID, MainApplet.class);
    }

    @Override
    public void sendPin(String pin) {
        simulator.selectApplet(appletAID);
        CommandAPDU commandAPDU = ApduFactory.sendPinApdu(pin);
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

        if (responseAPDU.getSW() != ReturnMsgConstants.SW_OK) {
            throw new CardRuntimeException("Failed to send pin. Card code: " + responseAPDU.getSW());
        }
    }

    @Override
    public void storeValue(String key, String value) {
        throw new NotImplementedException();
    }

    @Override
    public ArrayList<String> getSecretNames() {
        ArrayList<String> secretNames = new ArrayList<>();

        simulator.selectApplet(appletAID);
        CommandAPDU commandAPDU = ApduFactory.requestSecretNamesApdu();
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

        if (responseAPDU.getSW() != ReturnMsgConstants.SW_OK) {
            throw new CardRuntimeException("Failed to get secret names. Card code: " + responseAPDU.getSW());
        }

        return DataFormatProcessor.processKeyRequestApdu(responseAPDU.getData());
    }

    @Override
    public String revealSecret(String pin, String key) {
        return null;
    }

    @Override
    public void changePin(String oldPin, String newPin) {

    }

    @Override
    public ResponseAPDU sendApdu(short cla, short ins, short p1, short p2, byte[] data) {
        return null;
    }
}
