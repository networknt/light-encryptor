package com.networknt.encryptor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import static java.lang.System.exit;

/**
 * This is a new encryptor utility to encrypt the secret with stronger implementation.
 * Instead of using a static salt, we are generating a salt for each invocation to make
 * dictionary attack harder. Also, a master key is passed in to encrypt the secret.
 */
public class AESSaltEncryptor {
    public static String CRYPT_PREFIX = "CRYPT";

    public static void main(String [] args) {
        if(args.length < 2) {
            System.out.println("Please provide a master key and the plain text secret to encrypt!");
            System.out.println("java -jar encryptor.jar myKey mySecret");
            exit(0);
        }
        AESSaltEncryptor encryptor = new AESSaltEncryptor(args[0]);
        System.out.println(encryptor.encrypt(args[1]));
    }

    private static final int ITERATIONS = 65536;
    private static final int KEY_SIZE = 256;
    private static final int SALT_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final char[] password;
    private final SecureRandom secureRandom = new SecureRandom();

    public AESSaltEncryptor(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Password is required");
        }
        this.password = password.toCharArray();
    }

    /**
     * Encrypt given input string
     *
     * @param input String
     * @return encrypted value
     * @throws RuntimeException exception
     */
    public String encrypt(String input)
    {
        try
        {
            byte[] salt = randomBytes(SALT_LENGTH);
            byte[] iv = randomBytes(GCM_IV_LENGTH);
            SecretKeySpec secret = createSecret(salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
            cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] out = cipher.doFinal(inputBytes);
            return CRYPT_PREFIX + ":" + toHex(salt) + ":" + toHex(iv) + ":" + toHex(out);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("Unable to encrypt", e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("Unable to encrypt", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Unable to encrypt", e);
        } catch(NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to encrypt", e);
        } catch(InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Unable to encrypt", e);
        } catch(InvalidKeySpecException e) {
            throw new RuntimeException("Unable to encrypt", e);
        } catch(javax.crypto.NoSuchPaddingException e) {
            throw new RuntimeException("Unable to encrypt", e);
        }
    }

    private SecretKeySpec createSecret(byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private byte[] randomBytes(int length)
    {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private static String toHex(byte[] array) throws NoSuchAlgorithmException
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);

        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }
}
