package main.security;

import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import main.exceptions.CardRuntimeException;
import main.utils.ApduFactory;
import main.utils.constants.CardSettings;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;

public class JcSecureChannel implements ICipher {

    private RSACipher rsa;
    private AESCipher aes;
    private boolean initialized = false;

    @Override
    public byte[] encrypt(byte[] toEncrypt) {
        if (!initialized) {
            throw new CardRuntimeException("Secure channel is not initialized.");
        }

        return aes.encrypt(toEncrypt);
    }

    @Override
    public byte[] decrypt(byte[] toDecrypt) {
        if (!initialized) {
            throw new CardRuntimeException("Secure channel is not initialized.");
        }

        return aes.decrypt(toDecrypt);
    }

    public void setUpScReal (CardChannel channel) throws CardException {
        select(channel);
        rsa = new RSACipher();
        aes = new AESCipher();

        byte[] modulusBytes = rsa.getRSAModulusAsBytes();

        CommandAPDU apdu = ApduFactory.sendKeyApdu(
                Arrays.copyOfRange(modulusBytes, 0, 220)
        );

        ResponseAPDU response = channel.transmit(apdu);

        if ((short) response.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Error sending RSA pubkey to card. SW: "
                    + (short) response.getSW());
        }

        apdu = ApduFactory.sendKeyApdu(
                Arrays.copyOfRange(modulusBytes, 220, 256)
        );

        response = channel.transmit(apdu);

        if ((short) response.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Error sending RSA pubkey to card. SW: "
                    + (short) response.getSW());
        }

        //**************************GET KEY************************
        byte[] encKey = new byte[256];

        apdu = ApduFactory.requestSymKey((byte) 0x01);
        response = channel.transmit(apdu);
        System.arraycopy(response.getData(), 0, encKey, 0, 256);

        if ((short) response.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Error receiving AES key. SW: "
                    + (short) response.getSW());
        }

        aes.setKey(rsa.decrypt(encKey));

        initialized = true;
    }

    public void setUpScSim (CardSimulator simulator, AID aid) {

        simulator.selectApplet(aid);

        rsa = new RSACipher();
        aes = new AESCipher();

        byte[] modulusBytes = rsa.getRSAModulusAsBytes();

        CommandAPDU apdu = ApduFactory.sendKeyApdu(
                Arrays.copyOfRange(modulusBytes, 0, 220)
        );

        ResponseAPDU response = simulator.transmitCommand(apdu);

        if ((short) response.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Error sending RSA pubkey to card. SW: "
            + response.getSW());
        }

        apdu = ApduFactory.sendKeyApdu(
                Arrays.copyOfRange(modulusBytes, 220, 256)
        );

        response = simulator.transmitCommand(apdu);

        if ((short) response.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Error sending RSA pubkey to card. SW: "
                    + (short) response.getSW());
        }

        //**************************GET KEY************************
        byte[] encKey = new byte[256];

        apdu = ApduFactory.requestSymKey((byte) 0x01);
        response = simulator.transmitCommand(apdu);
        System.arraycopy(response.getData(), 0, encKey, 0, 256);

        if ((short) response.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Error receiving AES key. SW: "
                    + (short) response.getSW());
        }

        aes.setKey(rsa.decrypt(encKey));

        initialized = true;
    }


    /**
     * Selects the applet.
     *
     * @throws CardException Failed to select the applet
     */
    private void select(CardChannel channel) throws CardException {

        CommandAPDU commandAPDU = ApduFactory.selectAppletApdu(CardSettings.AID);
        ResponseAPDU responseAPDU = channel.transmit(commandAPDU);

        if ((short) responseAPDU.getSW() != ISO7816.SW_NO_ERROR) {
            throw new CardRuntimeException("Failed to select applet. Card code: " + (short) responseAPDU.getSW());
        }
    }
}
