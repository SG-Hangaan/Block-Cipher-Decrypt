package CipherDecrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESEncryptionDecryption {
    public static void main(String[] args) throws Exception {
    	
    	header();
        // Key and IV in hexadecimal format
        String keyHex = "2b7e151628aed2a6abf7158809cf4f3c";
        String ivHex = "000102030405060708090a0b0c0d0e0f";

        // Convert key and IV from hexadecimal to byte arrays
        byte[] keyBytes = hexStringToByteArray(keyHex);
        byte[] ivBytes = hexStringToByteArray(ivHex);

        // Create SecretKeySpec and IvParameterSpec objects
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // Create AES Cipher instance for CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Initialize Cipher for encryption with the key and IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        String plainText = "Welcome to Tutorialspoint";

        // Encrypt the plaintext
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

      
        // Convert encrypted byte array to hexadecimal format
        String encryptedHex = byteArrayToHexString(encryptedBytes);
        System.out.println("\nEncrypted Text (Hexadecimal): \n" + encryptedHex);

        // Initialize Cipher for decryption with the key and IV
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // Decrypt the encrypted bytes
        byte[] decryptedBytes = cipher.doFinal(hexStringToByteArray(encryptedHex));

        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("\nDecrypted Text: \n" + decryptedText);
    }

    private static void header() {
		System.out.println("Laboratory Experiment 6: Encryption and Decryption Method");
		System.out.println("Name: Sharon Grace T. Hangaan");
		System.out.println("3BSCS2");
	}

	// Helper method to convert a hexadecimal string to a byte array
    public static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                 + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    // Helper method to convert a byte array to a hexadecimal string
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    
    
    
    
}
