# light-encryptor
A command line utility to encrypt plain text secret into a string with prefix CRYPT

Most light-4j modules have a config file, and it might contain sensitive values that cannot be checked into the git repository in plain text. Users can use this command line utility to encrypt the sensitive value and check into the repository. During the runtime, the [Decryptor](https://doc.networknt.com/concern/decryptor/) class defined in the [config.yml](https://github.com/networknt/light-4j/blob/master/config/src/main/resources/config/config.yml) file will decrypt the encrypted text into plain text again. 


### Usage

This checkout builds the unreleased **1.1.0-SNAPSHOT** version. Build it with
Java 25 and Maven before using these commands:

```
mvn clean verify
java -jar target/light-encryptor-1.1.0-SNAPSHOT.jar "master-key" "secret"
```

The historical [1.0.0 artifact on Maven Central](https://repo1.maven.org/maven2/com/networknt/light-encryptor/1.0.0/light-encryptor-1.0.0.jar)
does not contain the migration entry point. Use the JAR built from this checkout;
these instructions do not announce a new published release.

The encrypted value is emitted in the AES-GCM format `CRYPT:<hex-salt>:<hex-iv>:<hex-ciphertext-and-tag>`.
This format is compatible with light-4j decryptor modules that support `CRYPT:salt:iv:hash`
and `AES/GCM/NoPadding`. Older light-4j decryptors that only support the legacy
three-part `CRYPT:salt:ciphertext` CBC format cannot decrypt newly generated values.

When running the above command on Windows, enclose the plain text into double quotes("") in the command line above. 

The master key should be configured on the target server as an environment variable or -D option in the java command line to start the light-4j server. 

It is recommended to use the same master key for all the services belonging to the same application. Or use the same master key per DevOps engineer. 

To learn how to set up the master key on the deployment server, please refer to the [decryptor](https://doc.networknt.com/concern/decryptor/).

If you want to decrypt a secret from the encrypted config file, you can use this [test case](https://github.com/networknt/light-4j/blob/master/decryptor/src/test/java/com/networknt/decrypt/AESDecryptorTest.java#L40). Also, you can find the document on how to use it at https://doc.networknt.com/concern/decryptor/


### Migrate legacy encrypted values

Older releases produced three-part `CRYPT:salt:ciphertext` values using AES-CBC.
Current light-4j decryptors require authenticated four-part AES-GCM values.
Use the offline migration command to decrypt a legacy value in memory and
re-encrypt it with a fresh salt and nonce. The original master key is required;
adding a fourth field to an old value cannot convert it.

Build this version first, then run from an interactive terminal:

```
java -cp target/light-encryptor-1.1.0-SNAPSHOT.jar com.networknt.encryptor.MigrationCli
```

Migration has its own entry point so the normal two-argument encryptor still
accepts every master key, including the literal `migrate`. The migration command
prompts without echo for the legacy value and original master key. By default it
prints only the replacement four-part value to the terminal's standard output;
prompts and diagnostics go to the terminal or standard error. Clear text is never
printed or written to a file.

To save the replacement value, use an explicit new output file:

```
java -cp target/light-encryptor-1.1.0-SNAPSHOT.jar com.networknt.encryptor.MigrationCli --output replacement.txt
```

Keep stdin and stdout attached to an interactive terminal. **Do not use `>` or
pipe stdout**: on the supported JDK, redirection makes `System.console()`
unavailable, preventing hidden prompts. `--output` saves only ciphertext while
keeping those prompts available. It refuses to overwrite an existing file and
creates owner-only (`0600`) permissions on POSIX filesystems; on other filesystems,
restrict access using the destination directory's access controls. The options
`--output` and `--rotate-key` can be combined in either order.

Detected input or cryptographic errors return a nonzero exit code without a
replacement. Output failures also return nonzero; discard any partial output or
file. Treat the generated value as sensitive configuration data.

To also rotate the master key:

```
java -cp target/light-encryptor-1.1.0-SNAPSHOT.jar com.networknt.encryptor.MigrationCli --rotate-key
```

This additionally prompts for and confirms the new master key. Configure that
key on the destination service when deploying the replacement value.

The migrator rejects invalid UTF-8 after CBC decryption, because the historical
encryptor accepted UTF-8 text. This catches additional wrong keys and corrupted
values, but **does not authenticate CBC**. A wrong key or damaged ciphertext can
still pass both padding and UTF-8 checks, so successful migration alone does not
prove the original secret was correct. Validate the migrated credential against
its target service in a controlled environment before deployment.

Back up the existing configuration, migrate each three-part value, and replace
only the corresponding values in a separate configuration copy. Leave existing
four-part values unchanged; this command accepts only legacy three-part inputs.
Validate all migrated credentials, then deploy the configuration with a GCM-capable
light-4j runtime and the chosen master key. Keep the original configuration and
key available for rollback with the old runtime until validation is complete.
The command does not rewrite configuration files or restore legacy CBC runtime
support. Its legacy conversion implementation is package-private and is not a
public library API.

Temporary plaintext bytes and owned password/key buffers are cleared on completion
where accessible; this is not a guarantee of complete JVM heap erasure.

### Build

```
mvn clean install
```


### Release

```
mvn clean install deploy -DperformRelease
```


