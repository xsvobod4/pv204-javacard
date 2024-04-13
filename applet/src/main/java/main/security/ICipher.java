package main.security;

public interface ICipher {
    byte[] encrypt(byte[] toEncrypt);
    byte[] decrypt(byte[] toDecrypt);
}
