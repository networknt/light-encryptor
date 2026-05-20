package com.networknt.encryptor;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

class AESSaltEncryptorTest {
    private static final int ITERATIONS = 65536;
    private static final int KEY_SIZE = 256;
    private static final int GCM_TAG_LENGTH = 128;

    @Test
    void encryptUsesLight4jDecryptorFormat() throws Exception {
        AESSaltEncryptor encryptor = new AESSaltEncryptor("light");
        String encrypted = encryptor.encrypt("secret");

        String[] parts = encrypted.split(":");
        Assertions.assertEquals(4, parts.length);
        Assertions.assertEquals(AESSaltEncryptor.CRYPT_PREFIX, parts[0]);
        Assertions.assertEquals(32, parts[1].length());
        Assertions.assertEquals(24, parts[2].length());
        Assertions.assertEquals("secret", decryptLikeLight4j(encrypted, "light"));
    }

    @Test
    void encryptUsesFreshSaltAndIv() {
        AESSaltEncryptor encryptor = new AESSaltEncryptor("light");

        String encrypted1 = encryptor.encrypt("secret");
        String encrypted2 = encryptor.encrypt("secret");

        Assertions.assertNotEquals(encrypted1, encrypted2);
        Assertions.assertNotEquals(encrypted1.split(":")[1], encrypted2.split(":")[1]);
        Assertions.assertNotEquals(encrypted1.split(":")[2], encrypted2.split(":")[2]);
    }

    private static String decryptLikeLight4j(String input, String password) throws Exception {
        String[] parts = input.split(":");
        byte[] salt = fromHex(parts[1]);
        byte[] iv = fromHex(parts[2]);
        byte[] hash = fromHex(parts[3]);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return new String(cipher.doFinal(hash), StandardCharsets.UTF_8);
    }

    private static byte[] fromHex(String hex)
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i < bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}
