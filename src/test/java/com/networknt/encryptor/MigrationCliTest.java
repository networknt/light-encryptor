package com.networknt.encryptor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class MigrationCliTest {
    @TempDir Path directory;

    @Test
    void everyTwoArgumentEncryptInvocationStillWorks() throws Exception {
        for (String secret : List.of("mySecret", "--rotate-key")) {
            Result result = launch(AESSaltEncryptor.class, "migrate", secret);
            assertEquals(0, result.status());
            assertEquals("", result.error());
            String[] parts = result.output().strip().split(":");
            assertEquals(4, parts.length);
            HexFormat hex = HexFormat.of();
            PBEKeySpec spec = new PBEKeySpec("migrate".toCharArray(), hex.parseHex(parts[1]), 65536, 256);
            try {
                byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, hex.parseHex(parts[2])));
                assertEquals(secret, new String(cipher.doFinal(hex.parseHex(parts[3])), StandardCharsets.UTF_8));
            } finally {
                spec.clearPassword();
            }
        }
    }

    @Test
    void separateMigrationEntryAcceptsValidOptionsAndRequiresTerminal() throws Exception {
        for (String[] args : new String[][]{{}, {"--rotate-key"}, {"--output", "result.txt"},
                {"--rotate-key", "--output", "result.txt"}, {"--output", "result.txt", "--rotate-key"}}) {
            Result result = launch(MigrationCli.class, args);
            assertEquals(1, result.status());
            assertEquals("", result.output());
            assertTrue(result.error().contains("Do not redirect stdout; use --output"));
        }
    }

    @Test
    void migrationEntryRejectsInvalidOptionsBeforePrompting() throws Exception {
        for (String[] args : new String[][]{{"unexpected"}, {"--bad"}, {"--output"},
                {"--output", ""}, {"--rotate-key", "extra"}, {"--rotate-key", "--rotate-key"},
                {"--output", "one", "--output", "two"}, {"--output", "--rotate-key"}}) {
            Result result = launch(MigrationCli.class, args);
            assertEquals(1, result.status());
            assertEquals("", result.output());
            assertTrue(result.error().contains("Usage:"));
            assertFalse(result.error().contains("Hidden prompts"));
        }
    }

    private Result launch(Class<?> entry, String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", Path.of(entry.getProtectionDomain().getCodeSource().getLocation().toURI()).toString(), entry.getName()));
        command.addAll(List.of(args));
        Path output = Files.createTempFile(directory, "stdout", ".txt");
        Path error = Files.createTempFile(directory, "stderr", ".txt");
        Process process = new ProcessBuilder(command).redirectOutput(output.toFile()).redirectError(error.toFile()).start();
        try {
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "CLI process timed out");
            return new Result(process.exitValue(), Files.readString(output), Files.readString(error));
        } finally {
            process.destroyForcibly();
        }
    }

    private record Result(int status, String output, String error) { }
}
