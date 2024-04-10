package main.utils;

import main.utils.constants.PathConstants;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Objects;

public class FileUtil {

    public static final String SECRETS_FILE = "src/main/resources/secrets.txt";

    //ChatGPT was used to generate this method
    public static void saveSecretPair(short slot, String secretName) {

        if (secretName.contains(",")) {
            throw new IllegalArgumentException("Secret name cannot contain a comma (,).");
        }

        if (secretName.isEmpty()) {
            throw new IllegalArgumentException("Secret name cannot be empty.");
        }

        if (secretName.contains("\n")) {
            throw new IllegalArgumentException("Secret name cannot contain a newline character.");
        }

        if (secretName.matches("[0-9]+")) {
            throw new IllegalArgumentException("Secret name cannot be a number by itself.");
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(SECRETS_FILE, true))) {
            writer.write(slot + "," + secretName);
            writer.newLine();
        } catch (IOException e) {
            throw new RuntimeException("Error appending file: " + SECRETS_FILE);
        }
    }

    //ChatGPT was used to generate this method
    public static HashMap<Short, String> loadSecretNames() {

        HashMap<Short, String> map = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(SECRETS_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 2) {
                    short key = Short.parseShort(parts[0]);
                    String value = parts[1];
                    map.put(key, value.trim());
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error loading file: " + SECRETS_FILE);
        } catch (NumberFormatException e) {
            throw new NumberFormatException("Error parsing integer while saving file.");
        }

        return map;
    }
}
