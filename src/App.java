import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Base64;


public class App {
    public static void main(String[] args) {
        Scanner cin = new Scanner(System.in);
        
        File keyFile = new File("../key");

        if (!keyFile.exists()) {
            // new user, prompt to create a key
            
        }
        
        Scanner keyFileScan;
        try {
            keyFileScan = new Scanner(keyFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.exit(1);
        }


    }

    private static void createKeyfile(File keyfile) {
        Scanner cin = new Scanner(System.in);
        
        System.out.println("No keyfile detected. Running as new user.\nCreate a passcode to access your new password manager.");
        String newPasscodeString = cin.nextLine();
            
        //TODO: create salt

        //TODO: hash passcode, store in keyfile
    }
}
