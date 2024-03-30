package main.utils;

import org.junit.jupiter.api.*;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

public class FileUtilTest {

    @Test
    public void testGetHashMap() {
        HashMap<Short, String> map =  FileUtil.loadSecretNames();
        assertNotNull(map);
        assertEquals(3, map.size());
        assertEquals("GOOGLE", map.get((short) 0));
        assertEquals("Office365", map.get((short) 1));
        assertEquals("xpepik@mail.muni.cz", map.get((short) 2));
    }

}