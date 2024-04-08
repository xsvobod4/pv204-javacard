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

        SecureChannel secureChannel = new SecureChannel();
        RSAPublicKey rsaPublicKey = secureChannel.getRSAPublicKey();
        byte[] modulusBytes = secureChannel.getRSAModulusAsBytes(rsaPublicKey);

//        byte[] modulusPat1 = Arrays.copyOfRange(modulusBytes, 0, 220);
////        System.arraycopy(modulusBytes, 0, modulusPat1, 0, 200);
//
//        byte[] modulusPat2 = Arrays.copyOfRange(modulusBytes, 220, 420);
////        System.arraycopy(modulusBytes, 200, modulusPat2, 0, 400);
//
//        byte[] modulusPat3 = Arrays.copyOfRange(modulusBytes, 420, 512);
////        System.arraycopy(modulusBytes, 400, modulusPat3, 0, 512);


        CommandAPDU commandAPDUSCInnit = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_SC_INIT, // INS_GET_SECRET_VALUE
                (byte) 0x00, // P1
                (byte) 0x00, // P2
                Arrays.copyOfRange(modulusBytes, 0, 220)
        );
        simulator.transmitCommand(commandAPDUSCInnit);


        CommandAPDU commandAPDUSCInnit2 = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_SC_INIT, // INS_GET_SECRET_VALUE
                (byte) 0x00, // P1
                (byte) 0x00, // P2
                Arrays.copyOfRange(modulusBytes, 220, 420)
        );
        simulator.transmitCommand(commandAPDUSCInnit2);


        CommandAPDU commandAPDUSCInnit3 = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_SC_INIT, // INS_GET_SECRET_VALUE
                (byte) 0x00, // P1
                (byte) 0x00, // P2
                Arrays.copyOfRange(modulusBytes, 420, 512)
        );
        simulator.transmitCommand(commandAPDUSCInnit3);
//**************************GET KEY************************

        byte[] encAESKey = new byte[512];

//        byte[] dataIndex = new byte[]{0x00, 0xFF};

        CommandAPDU commandAPDUSCgetKey1 = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_SC_GET_KEY, // INS_GET_SECRET_VALUE
                (byte) 0x00, // P1
                (byte) 0x00, // P2
                new byte[]{0x01}
        );
        ResponseAPDU responseAPDUSCgetKey1 =simulator.transmitCommand(commandAPDUSCgetKey1);
        System.arraycopy(responseAPDUSCgetKey1.getData(), 0, encAESKey, 0, 256);

        CommandAPDU commandAPDUSCgetKey2 = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_SC_GET_KEY, // INS_GET_SECRET_VALUE
                (byte) 0x00, // P1
                (byte) 0x00, // P2
                new byte[]{0x02}
        );
        ResponseAPDU responseAPDUSCgetKey2 =simulator.transmitCommand(commandAPDUSCgetKey2);
        System.arraycopy(responseAPDUSCgetKey2.getData(), 0, encAESKey, 256, 256);




        byte[] decryptedAESkey = secureChannel.decryptRSAWithPrivateKey(encAESKey, secureChannel.getRSAPrivateKey());


        SecretKeySpec aesKey = new SecretKeySpec(decryptedAESkey, "AES");
		System.out.println("Decrypted KEY length: " + decryptedAESkey.length);
		System.out.println("Decrypted KEY: " + new String(decryptedAESkey));

        ////// use aes key with encryption

//        [108, 85, 68, 121, 122, -111, 17, 93, -61, 51, 14, -67, 0, 56, 81, -46]
//        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, aesKey);

//        CommandAPDU commandAPDUList3 = new CommandAPDU(0x00, InstructionConstants.INS_GET_SECRET_NAMES, 0x00, 0x00);
//        byte[] apduData = commandAPDUList3.getData();

        // Encrypt the payload data

        byte[] DEFAULT_PIN = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte secretName = (byte) 0x01;




        //        byte[] encryptedAPDUData = cipher.doFinal(apduData);
        byte[] encryptedPIN = secureChannel.encryptAESWithKey(aesKey, DEFAULT_PIN);


        // Create a new CommandAPDU with the encrypted payload data
        CommandAPDU encryptedCommandAPDU = ApduFactory.genericApdu(
                (byte) 0x00, // CLA
                (byte) InstructionConstants.INS_REVEAL_SECRET, // INS_GET_SECRET_VALUE
                secretName, // P1
                (byte) 0x00, // P2
                DEFAULT_PIN         // Data
        );

//        CommandAPDU encryptedCommandAPDU = new CommandAPDU(0x00, InstructionConstants.INS_VERIFY_PIN, 0x00, 0x00, encryptedPIN);
        // Transmit the encrypted APDU
        ResponseAPDU responseList3 = simulator.transmitCommand(encryptedCommandAPDU);
        // Decrypt the response data

        // Initialize the Cipher for decryption


        // Decrypt the data
//        byte[] decryptedResponseData = cipher.doFinal(responseList3.getData());
        byte[] decryptedResponseData = secureChannel.decryptAESWithKey(aesKey, responseList3.getData());
        String decryptedResponse = new String(decryptedResponseData, StandardCharsets.UTF_8);        // Print the decrypted response
        System.out.println("List secrets:");
        System.out.println("Data length: " + decryptedResponseData.length);
        System.out.println(decryptedResponse);
    }
}



