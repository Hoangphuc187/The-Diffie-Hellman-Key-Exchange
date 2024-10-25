import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    
    public static void main(String[] args) {
        try {
            String serverIP = "127.0.0.1";
            int port = 12345;

            Socket socket = new Socket(serverIP, port);

      
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGen.initialize(1024);
            KeyPair clientKeyPair = keyPairGen.generateKeyPair();
            KeyAgreement clientKeyAgreement = KeyAgreement.getInstance("DiffieHellman");
            clientKeyAgreement.init(clientKeyPair.getPrivate());

        
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            byte[] serverPublicKeyBytes = (byte[]) in.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);

            PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);

            clientKeyAgreement.doPhase(serverPublicKey, true);

    
            out.writeObject(clientKeyPair.getPublic().getEncoded());

            byte[] sharedSecret = clientKeyAgreement.generateSecret();
            SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, 0, 16, "AES");

         
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter text: ");
            String plainText = scanner.nextLine();

          
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        
            out.writeObject(encryptedBytes);

            
            socket.close();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | ClassNotFoundException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}
