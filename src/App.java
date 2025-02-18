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

/**
 * @author Kavin Muthuselvan, Matthew Stall
 */ 
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

            String hashString = hashPrivateKey(newPasscodeString, saltString);
            String outputString = saltString + ":" + hashString + "\n";

            if (writeToFile(keyFile, outputString, false))
                System.out.println("Passcode creation success!\n");
            else {
                System.out.println("Passcode creation failed. Please try again.\n");
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

        System.out.println("Keyfile detected.");

        //  AUTHENTICATION

        keyFileScan.useDelimiter(":");
        String saltString = keyFileScan.next();
        String storedPrivateKeyHash = keyFileScan.nextLine();

        System.out.print("Enter your passcode to access Password Manager: ");
        String passcodeString = cin.nextLine();

        if (storedPrivateKeyHash.charAt(0) == ':') {
            storedPrivateKeyHash = storedPrivateKeyHash.substring(1);
        }

        while (!hashPrivateKey(passcodeString, saltString).equals(storedPrivateKeyHash)) {
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
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                cin.close();
                System.exit(1);
            }
            keyFileScan.nextLine();

            System.out.println("\nWelcome to Password Manager");
            System.out.print("\na: Add Password\nr: Read Password\nq: Quit\nEnter choice: ");
            String choice = cin.nextLine();

            switch (choice) {
                case "q": {
                    running = false;
                    System.out.println("Exiting Password Manager...");
                    break;
                }
                case "a": {
                    System.out.print("Enter label for password: ");
                    String label = cin.nextLine();

                    // Search for this label in the keyfile
                    boolean existing = false;
                    keyFileScan.useDelimiter(":");
                    while (!existing && keyFileScan.hasNextLine()) {
                        existing = keyFileScan.next().equals(label);

                        keyFileScan.nextLine();
                    }

                    // Prompt user to overwrite
                    String overwriteChoice = "";
                    if (existing) {
                        System.out.println("A Password with this label already exists, would you like to overwrite?");
                        System.out.print("\ny: Overwrite\nn: Go Back\nEnter choice: ");
                    
                        overwriteChoice = cin.nextLine();

                        if (!overwriteChoice.equals("y"))
                            continue;
                    }

                    System.out.print("Enter password to store: ");
                    String storedPassword = cin.nextLine();
                    
                    String encryptedPasscodeString = encryptMessage(storedPassword, passcodeString, saltString);
                    String outputString = label + ":" + encryptedPasscodeString + "\n";

                    if (existing)
                        replacePassword(label, encryptedPasscodeString, keyFile);
                    else
                        writeToFile(keyFile, outputString, true);

                    break;
                }
                case "r": {
                    System.out.print("Enter label for password: ");
                    String label = cin.nextLine();

                    String targetPassword = "";
                    
                    // Search for this label in the keyfile
                    boolean existing = false;
                    keyFileScan.useDelimiter(":");
                    while (!existing && keyFileScan.hasNextLine()) {
                        existing = keyFileScan.next().equals(label);

                        targetPassword = keyFileScan.nextLine();
                    }

                    targetPassword = targetPassword.substring(1); // Remove illegal character ":"

                    if (existing)
                        System.out.println("The stored password is: " + decryptMessage(targetPassword, passcodeString, saltString));
                    else
                        System.out.println("No password matches label \"" + label + "\"");

                    break;
                }
            }
        }

        keyFileScan.close();
        cin.close();
        System.exit(0);
    }

    /**
     * Returns a base64 encoded randomly generated salt string
     * @return A Base 64 encoded randomly generated salt string
     */
    private static String generateRandomSaltString() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Decrypts an encrypted string
     * @param message The encrypted message
     * @param passcode The passcode portion of the symmetric encryption key
     * @param saltString The salt portion of the symmetric encryption key
     * @return The decrypted message
     */
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

    /**
     * Replace line starting with specified label with a new password
     * @param label Label to match with the line to be overwritten
     * @param password New password
     * @param file File to access and replace password in
     */
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

    /**
     * Encrypts a string
     * @param message String to encrypt
     * @param passcode The passcode portion of the symmetric encryption key
     * @param saltString The salt portion of the symmetric encryption key
     * @return Resulting encrypted version of the string
     */
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

    /**
     * Generates a hashed and salted private key
     * @param passcode String to convert to a hash
     * @param saltString Salt to add to the hash
     * @return Resulting hashed string
     */
    private static String hashPrivateKey(String passcode, String saltString) {
    
        byte[] salt = Base64.getDecoder().decode(saltString);

        KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);

        SecretKeyFactory factory;
        SecretKey privateKey;

        try {
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

    /**
     * Writes to a specified file
     * @param file File to write output string to
     * @param output String to write
     * @param append If true, appends string at end of file. If false, overwrites starting with the beginning of the file
     * @return Returns true if the file process was successful
     */
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
