package com.networknt.encryptor;

import java.nio.file.Path;

/** Separate offline entry point; preserves every existing encryptor key/secret invocation. */
public final class MigrationCli {
    private MigrationCli() { }

    /**
     * Runs offline migration with optional key rotation and output file.
     * @param args optional --rotate-key and --output new-file
     */
    public static void main(String[] args) {
        boolean rotateKey = false;
        Path output = null;
        try {
            for (int i = 0; i < args.length; i++) {
                if ("--rotate-key".equals(args[i]) && !rotateKey) {
                    rotateKey = true;
                } else if ("--output".equals(args[i]) && output == null && i + 1 < args.length
                        && !args[i + 1].startsWith("--") && !args[i + 1].isBlank()) {
                    output = Path.of(args[++i]);
                } else {
                    throw new IllegalArgumentException();
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Usage: java -cp <built-jar> com.networknt.encryptor.MigrationCli "
                    + "[--rotate-key] [--output <new-file>]");
            System.exit(1);
        }
        System.exit(LegacyCryptMigrator.run(System.console(), System.out, System.err, rotateKey, output));
    }
}
