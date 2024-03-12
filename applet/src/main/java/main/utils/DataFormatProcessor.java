package main.utils;

import java.util.ArrayList;

public class DataFormatProcessor {
    private static final short LENGTH_KEY = (short) 1; //1 byte
    private static final short LENGTH_DATA = (short) 255; //2040 bits or 255 bytes

    //TODO: Write a test for this
    public static ArrayList<String> processKeyRequestApdu(byte[] data) {
        ArrayList<byte[]> result = new ArrayList<>();
        short chunkSize = LENGTH_KEY;

        for (short i = 0; i < data.length; i++) {
            byte[] chunk = new byte[chunkSize];
            System.arraycopy(data, i, chunk, 0, chunkSize);
            result.add(chunk);
        }

        ArrayList<String> secretNames = new ArrayList<>();

        for (byte[] chunk : result) {
            secretNames.add(TypeConverter.bytesToHex(chunk));
        }

        return secretNames;
    }
}
