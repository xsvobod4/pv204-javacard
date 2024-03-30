package main.utils;

import java.io.Console;
import java.util.Arrays;

public class ConsoleWrapper {

    public static String readPassword(String msg) {
        Console console = System.console();
        return new String(console.readPassword(msg));
    }

    public static String readLine(String msg) {
        Console console = System.console();
        return console.readLine(msg);
    }
}
