package com.networknt.encryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/** Offline conversion of legacy CBC values to authenticated GCM values. */
public final class LegacyCryptMigrator {
    private LegacyCryptMigrator() { }

    static int run(Console console, PrintStream output, PrintStream error, boolean rotateKey) {
        if (console == null) {
            error.println("Migration requires an interactive terminal for hidden master-key prompts.");
            return 1;
        }
        char[] oldKey = null;
        char[] newKey = null;
        char[] confirmation = null;
        char[] input = null;
        try {
            error.println("Legacy CBC cannot authenticate the original value. Validate the migrated secret before deployment.");
            input = console.readPassword("Legacy CRYPT value (hidden): ");
            if (input == null) throw new IllegalArgumentException();
            oldKey = console.readPassword("Original master key: ");
            newKey = oldKey;
            if (rotateKey) {
                newKey = console.readPassword("New master key: ");
                confirmation = console.readPassword("Confirm new master key: ");
                if (newKey == null || !Arrays.equals(newKey, confirmation)) {
                    error.println("New master keys do not match.");
                    return 1;
                }
            }
            output.println(migrate(new String(input), oldKey, newKey));
            return 0;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // Never include exception messages, input values, or plaintext in diagnostics.
            error.println("Migration failed. Check the legacy format and master key; no replacement was emitted.");
            return 1;
        } finally {
            clear(input);
            clear(oldKey);
            clear(newKey);
            clear(confirmation);
        }
    }

    /**
     * Converts one legacy value, without changing the caller's password arrays.
     * CBC has no authentication: callers must independently validate the result.
     *
     * @param value legacy CRYPT:salt:ciphertext value
     * @param oldPassword original master key
     * @param newPassword destination master key
     * @return four-part AES-GCM value
     * @throws GeneralSecurityException if decryption or encryption fails
     * @throws IllegalArgumentException if input is malformed or a key is blank
     */
    public static String migrate(String value, char[] oldPassword, char[] newPassword)
            throws GeneralSecurityException {
        requirePassword(oldPassword);
        requirePassword(newPassword);
        if (value == null) throw new IllegalArgumentException("Legacy CRYPT value is required.");
        String[] parts = value.split(":", -1);
        if (parts.length != 3 || !"CRYPT".equals(parts[0]) || parts[1].length() != 32
                || parts[2].isEmpty() || parts[2].length() % 32 != 0) {
            throw new IllegalArgumentException("Expected legacy CRYPT:salt:ciphertext.");
        }
        HexFormat hex = HexFormat.of();
        byte[] oldSalt = hex.parseHex(parts[1]);
        byte[] ciphertext = hex.parseHex(parts[2]);
        byte[] plaintext = null;
        byte[] oldKey = null;
        byte[] newKey = null;
        try {
            oldKey = derive(oldPassword, oldSalt);
            Cipher decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decoder.init(Cipher.DECRYPT_MODE, new SecretKeySpec(oldKey, "AES"), new IvParameterSpec(new byte[16]));
            plaintext = decoder.doFinal(ciphertext);

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            random.nextBytes(salt);
            random.nextBytes(nonce);
            newKey = derive(newPassword, salt);
            Cipher encoder = Cipher.getInstance("AES/GCM/NoPadding");
            encoder.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(newKey, "AES"), new GCMParameterSpec(128, nonce));
            return "CRYPT:" + hex.formatHex(salt) + ":" + hex.formatHex(nonce) + ":"
                    + hex.formatHex(encoder.doFinal(plaintext));
        } finally {
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
            if (oldKey != null) Arrays.fill(oldKey, (byte) 0);
            if (newKey != null) Arrays.fill(newKey, (byte) 0);
        }
    }

    private static byte[] derive(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void requirePassword(char[] password) {
        if (password != null) {
            for (char ch : password) {
                if (!Character.isWhitespace(ch)) return;
            }
        }
        throw new IllegalArgumentException("A nonblank master key is required.");
    }

    private static void clear(char[] value) {
        if (value != null) Arrays.fill(value, '\0');
    }
}
