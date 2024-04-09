package main;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class ClientAppTest {

    @Test
    public void testCorrectSetSecret() {
        assertAll(() -> {
            ClientApp.main(new String[]{"--sim", "-i", "set", "-p", "1234", "-v", "Secret1", "-k", "GOOGLE", "-o"});
        });
    }

    @Test
    public void testCorrectRevealSecret() {
        assertAll(() -> {
            ClientApp.main(new String[]{"--sim", "-i", "reveal_secret", "-p", "1234", "-k", "xpepik@mail.muni.cz"});
        });
    }

    @Test
    public void testCorrectChangePin() {
        assertAll(() -> {
            ClientApp.main(new String[]{"--sim", "-i", "change_pin", "-p", "1234", "-n", "4321"});
        });
    }

    @Test
    public void listSecretNames() {
        assertAll(() -> {
            ClientApp.main(new String[]{"--sim", "-i", "get_secret_names"});
        });
    }
}