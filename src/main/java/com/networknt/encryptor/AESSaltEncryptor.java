package com.networknt.encryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import static java.lang.System.exit;

/** Encrypts configuration secrets using a fresh salt and authenticated AES-GCM. */
public class AESSaltEncryptor {
    public static String CRYPT_PREFIX = "CRYPT";

    public static void main(String [] args) {
        if(args.length < 2) {
            System.out.println("Please provide a master key and the plain text secret to encrypt!");
            System.out.println("java -jar encryptor.jar myKey mySecret");
            exit(0);
        } else {
            AESSaltEncryptor encryptor = new AESSaltEncryptor(args[0]);
            System.out.println(encryptor.encrypt(args[1]));
        }
    }

    private static final int ITERATIONS = 65536;
    private static final int KEY_SIZE = 256;
    private static final int SALT_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final char[] password;

    public AESSaltEncryptor(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Password is required");
        }
        this.password = password.toCharArray();
    }

    /**
     * Encrypts the given UTF-8 input string.
     * @param input clear text
     * @return four-part encrypted value
     */
    public String encrypt(String input) {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        try {
            return encryptBytes(bytes, password);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Unable to encrypt", e);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    // Shared current-format encryption path for normal encryption and offline migration.
    static String encryptBytes(byte[] input, char[] password) throws GeneralSecurityException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(salt);
        random.nextBytes(iv);
        byte[] key = deriveKey(password, salt, ITERATIONS, KEY_SIZE);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            HexFormat hex = HexFormat.of();
            return CRYPT_PREFIX + ":" + hex.formatHex(salt) + ":" + hex.formatHex(iv) + ":"
                    + hex.formatHex(cipher.doFinal(input));
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static byte[] deriveKey(char[] password, byte[] salt, int iterations, int keySize)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keySize);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}
