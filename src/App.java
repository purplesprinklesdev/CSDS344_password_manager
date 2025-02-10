import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;


public class App {
    private static String KEY_GEN_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static int PBKDF2_ITERATIONS = 1024;
    private static int PBKDF2_KEY_LENGTH = 128;

    public static void main(String[] args) {
        Scanner cin = new Scanner(System.in);
        
        File keyFile = new File("./.key");

        if (!keyFile.exists()) {
            // new user, prompt to create a key
            System.out.print("No keyfile detected. Running as new user.\nCreate a passcode that you will use to access your new password manager.\nCreate passcode: ");
            String newPasscodeString = cin.nextLine();

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            String saltString = Base64.getEncoder().encodeToString(salt);

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

        while (getPrivateKeyHashed(passcodeString, saltString).equals(storedPrivateKeyHash)) {
            System.out.println("Incorrect Passcode");
            System.out.print("Enter your passcode to access Password Manager: ");
            passcodeString = cin.nextLine();
        }
        
        // PASSWORD MANAGER UNLOCKED

        Boolean running = true;

        while (running) {
            System.out.println("\na: Add Password\nb: Read Password\nq: Quit\nEnter choice: ");
            String choice = cin.nextLine();

            if (choice.equals("q")) {
                running = false;
            } else if (choice.equals("a")) {

                System.out.println("Enter label for password: ");
                String label = cin.nextLine();
                System.out.println("\nEnter password to store: ");
                passcodeString = cin.nextLine();
                keyFileScan.useDelimiter("\n");

                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[16];
                random.nextBytes(salt);

                saltString = Base64.getEncoder().encodeToString(salt);

                String hashString = getPrivateKeyHashed(passcodeString, saltString);
                String outputString = label + "\n" + saltString + ":" + hashString + "\n";

                if (keyFileScan.findAll(label).count() == 0) {
                    writeToFile(keyFile, outputString, true);
                } else {
                    // Replace File
                }
            }
        }

        //TODO: adding passwords


        //TODO: reading passwords


        keyFileScan.close();
        cin.close();
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
