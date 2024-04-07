package main;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import main.utils.ApduFactory;
import main.utils.TypeConverter;
import main.utils.constants.InstructionConstants;
import main.utils.constants.ReturnMsgConstants;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class TestingClientApp {


    public static void main(String[] args) throws Exception {
        // 1. create simulator
        CardSimulator simulator = new CardSimulator();

        TerminalFactory terminalFactory = TerminalFactory.getDefault();

        // 2. install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, MainApplet.class);

        // 3. select applet
        simulator.selectApplet(appletAID);

        // 4. send APDU
/*        CommandAPDU commandAPDUList = ApduFactory.requestSecretNamesApdu();
        ResponseAPDU responseList = simulator.transmitCommand(commandAPDUList);
        System.out.println("List secrets:");
        System.out.println("Data length:" + responseList.getData().length);
        System.out.println(new String(responseList.getData()));

        byte[] secretNames = responseList.getData();
        //Simply prints the secret names onto the screen. Can be used for piping.
        for (short i = (short) 0; i < secretNames.length; i++) {
            if (secretNames[i] == ReturnMsgConstants.SECRET_FILLED) {
                System.out.println(i);
            }
        }
        System.out.println("-------------");*/


    /*

        byte[] DEFAULT_PIN = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte secretName = (byte) 0x01;

        CommandAPDU revealSecretApdu = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_REVEAL_SECRET, // INS_GET_SECRET_VALUE
                secretName, // P1
                (byte) 0x00, // P2
                DEFAULT_PIN         // Data
        );
        // Transmit the APDU command to the JavaCard applet
        ResponseAPDU responseReveal = simulator.transmitCommand(revealSecretApdu);
        System.out.println("Reveal secret:");
        System.out.println(new String(responseReveal.getData()));
        System.out.println("SW: " + (short) responseReveal.getSW());

        CommandAPDU commandGetState = new CommandAPDU(0x00, InstructionConstants.INS_GET_STATE, 0x00, 0x00);
        ResponseAPDU responseGetState = simulator.transmitCommand(commandGetState);
        System.out.println("Get state:");
        System.out.println(TypeConverter.bytesToHex(responseGetState.getData()));


        //CommandAPDU pinCheck = new CommandAPDU(0x00, 0x04, 0x00, 0x00, DEFAULT_PIN);
        //ResponseAPDU responseVerifyPIN = simulator.transmitCommand(pinCheck);
//        System.out.println(TypeConverter.bytesToHex(responseVerifyPIN.getData()));



        byte[] NEW_PIN = new byte[]{0x06, 0x02, 0x07, 0x06};
        byte[] pinData = new byte[8];

        // Create a new buffer with space for the length byte and the PIN bytes

        System.arraycopy(DEFAULT_PIN, 0, pinData, 0, DEFAULT_PIN.length);
        System.arraycopy(NEW_PIN, 0, pinData, DEFAULT_PIN.length, NEW_PIN.length);

        CommandAPDU pinChange = new CommandAPDU(0x00, InstructionConstants.INS_CHANGE_PIN, 0x00, 0x00, pinData);
        ResponseAPDU responseChangePIN = simulator.transmitCommand(pinChange);
        System.out.println("Change PIN:");
        System.out.println("Rtr: " + (short) responseChangePIN.getSW());
        System.out.println("0x9000: " + (short) 0x9000);

*/
        /////////////////////////////////////////////////////// secure channel test:

        SecureChannel secureChannel = new SecureChannel();
        RSAPublicKey rsaPublicKey = secureChannel.getRSAPublicKey();
        byte[] modulusBytes = secureChannel.getRSAModulusAsBytes(rsaPublicKey);

        CommandAPDU commandAPDUSCInnit = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_SC_INIT, // INS_GET_SECRET_VALUE
                (byte) 0x00, // P1
                (byte) 0x00, // P2
                modulusBytes         // Data
        );
        ResponseAPDU responseAPDUSCInnit = simulator.transmitCommand(commandAPDUSCInnit);

        byte[] decryptedAESkey = secureChannel.decryptRSAWithPrivateKey(responseAPDUSCInnit.getData(), secureChannel.getRSAPrivateKey());
		SecretKeySpec aesKey = new SecretKeySpec(decryptedAESkey, "AES");
		System.out.println("Decrypted KEY length: " + decryptedAESkey.length);
		System.out.println("Decrypted KEY: " + new String(decryptedAESkey));
        ////////////////////////// konec ustanovení aes klíče


        //   request list of secrets - comes back encrypted
        CommandAPDU commandAPDUListSecrets = new CommandAPDU(0x20, InstructionConstants.INS_GET_SECRET_NAMES, 0x00, 0x00);
        // CommandAPDU commandAPDUListSecrets = ApduFactory.requestSecretNamesApdu();
        ResponseAPDU responseList3 = simulator.transmitCommand(commandAPDUListSecrets);

        byte[] decryptedResponseData = secureChannel.decryptAESWithKey(aesKey, responseList3.getData());
        for (short i = (short) 0; i < decryptedResponseData.length; i++) {
            if (decryptedResponseData[i] == ReturnMsgConstants.SECRET_FILLED) {
                System.out.println(i);
            }
        }

        // encrypted reveal secret:
        byte[] DEFAULT_PIN = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte secretName = (byte) 0x01;
        byte[] encryptedPIN = secureChannel.encryptAESWithKey(aesKey, DEFAULT_PIN);
        CommandAPDU revealSecretApdu = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_REVEAL_SECRET, // INS_GET_SECRET_VALUE
                secretName, // P1
                (byte) 0x00, // P2
                encryptedPIN         // Data
        );
        // Transmit the APDU command to the JavaCard applet
        ResponseAPDU responseReveal = simulator.transmitCommand(revealSecretApdu);

        byte[] decryptedResponseDataReveal = secureChannel.decryptAESWithKey(aesKey, responseReveal.getData());
        System.out.println("Reveal secret:");
// Decode the decrypted response using UTF-8 encoding
        String decryptedResponseString = new String(decryptedResponseDataReveal, StandardCharsets.UTF_8);
        System.out.println(decryptedResponseString);
        System.out.println("SW: " + (short) responseReveal.getSW());


    }
}



