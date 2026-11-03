package com.networknt.encryptor;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.PrintStream;
import java.io.IOException;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

/** Offline conversion of legacy CBC values to authenticated GCM values. */
final class LegacyCryptMigrator {
    // Frozen historical parameters, independent of future current-format changes.
    private static final int LEGACY_ITERATIONS = 65536;
    private static final int LEGACY_KEY_SIZE = 256;
    private LegacyCryptMigrator() { }

    static int run(Console console, PrintStream output, PrintStream error, boolean rotateKey) {
        return run(console, output, error, rotateKey, null);
    }

    static int run(Console console, PrintStream output, PrintStream error, boolean rotateKey, Path outputFile) {
        if (console == null) {
            error.println("Hidden prompts require stdin and stdout attached to a terminal. "
                    + "Do not redirect stdout; use --output <new-file> to save the result.");
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
            if (isBlank(oldKey)) {
                error.println("Original master key must not be blank.");
                return 1;
            }
            newKey = oldKey;
            if (rotateKey) {
                newKey = console.readPassword("New master key: ");
                if (isBlank(newKey)) {
                    error.println("New master key must not be blank.");
                    return 1;
                }
                confirmation = console.readPassword("Confirm new master key: ");
                if (newKey == null || !Arrays.equals(newKey, confirmation)) {
                    error.println("New master keys do not match.");
                    return 1;
                }
            }
            String replacement = migrate(new String(input), oldKey, newKey);
            if (outputFile == null) {
                output.println(replacement);
                output.flush();
                if (output.checkError()) {
                    error.println("Unable to write the replacement value. Discard any partial output.");
                    return 1;
                }
            } else {
                writeNewFile(outputFile, replacement);
            }
            return 0;
        } catch (CharacterCodingException e) {
            error.println("Legacy plaintext is not valid UTF-8. Check the original master key and ciphertext; no replacement was emitted.");
            return 1;
        } catch (IOException e) {
            error.println("Unable to create or write the output file. Use a new writable path; discard any partial file.");
            return 1;
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
    static String migrate(String value, char[] oldPassword, char[] newPassword)
            throws GeneralSecurityException, CharacterCodingException {
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
        try {
            oldKey = AESSaltEncryptor.deriveKey(oldPassword, oldSalt, LEGACY_ITERATIONS, LEGACY_KEY_SIZE);
            Cipher decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decoder.init(Cipher.DECRYPT_MODE, new SecretKeySpec(oldKey, "AES"), new IvParameterSpec(new byte[16]));
            plaintext = decoder.doFinal(ciphertext);
            validateUtf8(plaintext);
            return AESSaltEncryptor.encryptBytes(plaintext, newPassword);
        } finally {
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
            if (oldKey != null) Arrays.fill(oldKey, (byte) 0);
        }
    }

    private static void validateUtf8(byte[] plaintext) throws CharacterCodingException {
        char[] characters = new char[plaintext.length];
        try {
            var decoder = StandardCharsets.UTF_8.newDecoder();
            CharBuffer buffer = CharBuffer.wrap(characters);
            var decoded = decoder.decode(ByteBuffer.wrap(plaintext), buffer, true);
            if (decoded.isError()) decoded.throwException();
            var flushed = decoder.flush(buffer);
            if (flushed.isError()) flushed.throwException();
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    private static void requirePassword(char[] password) {
        if (isBlank(password)) throw new IllegalArgumentException("A nonblank master key is required.");
    }

    private static boolean isBlank(char[] password) {
        if (password != null) {
            for (char ch : password) {
                if (!Character.isWhitespace(ch)) return false;
            }
        }
        return true;
    }

    private static void writeNewFile(Path path, String replacement) throws IOException {
        FileAttribute<?>[] attributes = Files.getFileStore(path.toAbsolutePath().getParent())
                .supportsFileAttributeView("posix")
                ? new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        try (var channel = Files.newByteChannel(path,
                Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attributes);
             Writer writer = Channels.newWriter(channel, StandardCharsets.UTF_8)) {
            writer.write(replacement);
            writer.write(System.lineSeparator());
        }
    }

    private static void clear(char[] value) {
        if (value != null) Arrays.fill(value, '\0');
    }
}
