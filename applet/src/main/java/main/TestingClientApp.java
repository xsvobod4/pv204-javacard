package main;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import main.utils.ApduFactory;
import main.utils.TypeConverter;
import main.utils.constants.InstructionConstants;

import javax.crypto.Cipher;
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
        CommandAPDU commandAPDUList = new CommandAPDU(0x00, InstructionConstants.INS_GET_SECRET_NAMES, 0x00, 0x00);
        ResponseAPDU responseList = simulator.transmitCommand(commandAPDUList);
        System.out.println("List secrets:");
        System.out.println("Data length:" + responseList.getData().length);
        System.out.println(new String(responseList.getData()));


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

        //////establish aes key

        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        byte[] modulusBytesWithSign = rsaPublicKey.getModulus().toByteArray();
        byte[] modulusBytes;
        if (modulusBytesWithSign[0] == 0) {
            modulusBytes = Arrays.copyOfRange(modulusBytesWithSign, 1, modulusBytesWithSign.length);
        } else {
            modulusBytes = modulusBytesWithSign;
        }
        CommandAPDU commandAPDUSCInnit = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_SC_INIT, // INS_GET_SECRET_VALUE
                (byte) 0x00, // P1
                (byte) 0x00, // P2
                modulusBytes         // Data
        );
        ResponseAPDU responseAPDUSCInnit = simulator.transmitCommand(commandAPDUSCInnit);

        byte[] decryptedAESkey = decryptWithPrivateKey(responseAPDUSCInnit.getData(), keyPair.getPrivate());
        SecretKeySpec aesKey = new SecretKeySpec(decryptedAESkey, "AES");
        System.out.println("Decrypted KEY length: " + decryptedAESkey.length);
        System.out.println("Decrypted KEY: " + new String(decryptedAESkey));

        ////// use aes key with encryption

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);

        CommandAPDU commandAPDUList3 = new CommandAPDU(0x00, InstructionConstants.INS_GET_SECRET_NAMES, 0x00, 0x00);
        byte[] apduData = commandAPDUList3.getData();
        // Encrypt the payload data
        byte[] encryptedAPDUData = cipher.doFinal(apduData);
        // Create a new CommandAPDU with the encrypted payload data
        CommandAPDU encryptedCommandAPDU = new CommandAPDU(0x00, InstructionConstants.INS_GET_SECRET_NAMES, 0x00, 0x00, encryptedAPDUData);
        // Transmit the encrypted APDU
        ResponseAPDU responseList3 = simulator.transmitCommand(encryptedCommandAPDU);
        // Decrypt the response data
        byte[] decryptedResponseData = cipher.doFinal(responseList3.getData());
        String decryptedResponse = new String(decryptedResponseData, StandardCharsets.UTF_8);        // Print the decrypted response
        System.out.println("List secrets:");
        System.out.println("Data length: " + decryptedResponseData.length);
        System.out.println(decryptedResponse);

    }


    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

}



