package server.security;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoManager {
	
	public static final String CREDENTIALS_FILE = "device_credentials.txt";

	// -------------------------------------------------------------------------
	// 2. Utilidades RSA (assimétrica)
	// -------------------------------------------------------------------------
	public static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey targetPublicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, targetPublicKey);
		return cipher.doFinal(symmetricKey.getEncoded());
	}

	public static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] keyBytes = cipher.doFinal(encryptedKey);
		return new SecretKeySpec(keyBytes, "AES");
	}

	public static PublicKey reconstructPublicKey(String pubKeyB64) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(pubKeyB64);
		return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
	}

	// -------------------------------------------------------------------------
	// 3. Utilidades AES (simétrica)
	// -------------------------------------------------------------------------
	public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		return keyGen.generateKey();
	}

	public static byte[] encryptAES(String data, SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data.getBytes());
	}

	public static String decryptAES(byte[] data, SecretKey key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(data));
	}
}
