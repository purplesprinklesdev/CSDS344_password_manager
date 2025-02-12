import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

// TODO: Comments, Docstring and Authors
// TODO: Prompt user if the want to replace a password or not

public class App {
    private static final String KEY_GEN_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERATIONS = 1024;
    private static final int PBKDF2_KEY_LENGTH = 128;

    public static void main(String[] args) {
        Scanner cin = new Scanner(System.in);
        
        File keyFile = new File("./.key");

        if (!keyFile.exists()) {
            // new user, prompt to create a key
            System.out.print("No keyfile detected. Running as new user.\nCreate a passcode that you will use to access your new password manager.\nCreate passcode: ");
            String newPasscodeString = cin.nextLine();

            String saltString = generateRandomSaltString();

            String hashString = getPrivateKeyHashed(newPasscodeString, saltString);
            String outputString = saltString + ":" + hashString + "\n";

            if (writeToFile(keyFile, outputString, false))
                System.out.println("Passcode creation success!\n");
            else {
                System.out.println("Passcode creation failed.\n");
                System.exit(1);
            }
        }

        Scanner keyFileScan;
        try {
            keyFileScan = new Scanner(keyFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            cin.close();
            System.exit(1);
            return;
        }

        //  AUTHENTICATION

        keyFileScan.useDelimiter(":");
        String saltString = keyFileScan.next();
        String storedPrivateKeyHash = keyFileScan.nextLine();

        System.out.print("Enter your passcode to access Password Manager: ");
        String passcodeString = cin.nextLine();

        if (storedPrivateKeyHash.charAt(0) == ':') {
            storedPrivateKeyHash = storedPrivateKeyHash.substring(1);
        }

        while (!getPrivateKeyHashed(passcodeString, saltString).equals(storedPrivateKeyHash)) {
            System.out.println("Incorrect Passcode");
            System.out.print("Enter your passcode to access Password Manager: ");
            passcodeString = cin.nextLine();
        }
        
        // PASSWORD MANAGER UNLOCKED

        boolean running = true;

        while (running) {
            keyFileScan.close();
            try {
                keyFileScan = new Scanner(keyFile);
                keyFileScan.nextLine();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }

            System.out.print("\na: Add Password\nb: Read Password\nq: Quit\nEnter choice: ");
            String choice = cin.nextLine();

            switch (choice) {
                case "q" -> {
                    running = false;
                }
                case "a" -> {

                    System.out.print("Enter label for password: ");
                    String label = cin.nextLine();
                    System.out.print("Enter password to store: ");
                    String storedPassword = cin.nextLine();
                    keyFileScan.useDelimiter("\n");

                    String encryptedPasscodeString = encryptMessage(storedPassword, passcodeString, saltString);
                    String outputString = label + ":" + encryptedPasscodeString + "\n";

                    if (keyFileScan.findAll(label).count() == 0) {
                        writeToFile(keyFile, outputString, true);
                    } else {
                        replacePassword(label, encryptedPasscodeString, keyFile);
                    }
                }
                case "b" -> {
                    keyFileScan.useDelimiter("\n");
                    System.out.print("Enter label for password: ");
                    String label = cin.nextLine();
                    String[] labelPassPair = new String[1];

                    boolean found = false;
                    while (!found && keyFileScan.hasNext()) {
                        labelPassPair = keyFileScan.nextLine().split(":");
                        if (labelPassPair[0].equals(label)) {
                            found=true;
                        }
                    }

                    if (found)
                        System.out.println("The stored password is: " + decryptMessage(labelPassPair[1], passcodeString, saltString));
                    else
                        System.out.println("No password matches this label!");
                }
            }
        }

        keyFileScan.close();
        cin.close();
    }

    private static String generateRandomSaltString() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }

    private static String decryptMessage(String message, String passcode, String saltString) {
        try {
            byte[] salt = Base64.getDecoder().decode(saltString);
            byte[] encryptedData = Base64.getDecoder().decode(message);

            // Apparently we need to handle these (IVs) otherwise decryption with PBKDF2 doesn't work properly
            byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);
            byte[] actualCiphertext = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);

            KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_GEN_ALGORITHM);
            SecretKey privateKey = factory.generateSecret(spec);
            SecretKeySpec keySpec = new SecretKeySpec(privateKey.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            byte[] decryptedData = cipher.doFinal(actualCiphertext);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    private static void replacePassword(String label, String password, File file) {
        String[] labelPassPair = new String[1];
        Scanner keyFileScan = null;
        try {
            keyFileScan = new Scanner(file);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }

        StringBuilder builder = new StringBuilder();

        boolean found = false;
        while (!found && keyFileScan.hasNext()) {
            String line = keyFileScan.nextLine();
            labelPassPair = line.split(":");
            if (labelPassPair[0].equals(label)) {
                builder.append(label).append(":").append(password).append("\n");
            } else
                builder.append(line).append("\n");
        }

        keyFileScan.close();

        writeToFile(file, builder.toString(), false);
    }


    private static String encryptMessage(String message, String passcode, String saltString) {
        try {
            byte[] salt = Base64.getDecoder().decode(saltString);
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_GEN_ALGORITHM);
            SecretKey privateKey = factory.generateSecret(spec);
            SecretKeySpec keySpec = new SecretKeySpec(privateKey.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

            byte[] encryptedData = cipher.doFinal(message.getBytes());

            byte[] ivCipherCombined = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, ivCipherCombined, 0, iv.length);
            System.arraycopy(encryptedData, 0, ivCipherCombined, iv.length, encryptedData.length);

            return Base64.getEncoder().encodeToString(ivCipherCombined);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }


    private static String getPrivateKeyHashed(String passcode, String saltString) {
    
        byte[] salt = Base64.getDecoder().decode(saltString);

        KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);

        SecretKeyFactory factory;
        SecretKey privateKey;

        try { // TODO: better error handling
            factory = SecretKeyFactory.getInstance(KEY_GEN_ALGORITHM);
            privateKey = factory.generateSecret(spec);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }


        byte[] hash = privateKey.getEncoded();
        String hashString = Base64.getEncoder().encodeToString(hash);

        return hashString;
    }

    private static boolean writeToFile(File file, String output, boolean append) {
        try {
            if (!file.exists())
                file.createNewFile();
            
            FileOutputStream stream = new FileOutputStream(file, append);
            byte[] bytes = output.getBytes();
            stream.write(bytes);
            stream.close();

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to write to file. Please try again.");
            System.exit(1);
            return false;
        }
    }
}
