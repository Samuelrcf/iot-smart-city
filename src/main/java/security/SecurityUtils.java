package security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.ObjectInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecurityUtils {

	public static final String CREDENTIALS_FILE = "device_credentials.txt";

	private static final String PUBLIC_KEY_FILE = "edge_public.key";
	private static final String PRIVATE_KEY_FILE = "edge_private.key";

	private static PublicKey edgePublicKey;
	private static PrivateKey edgePrivateKey;

	// Bloco estático carrega as chaves do disco na inicialização de CADA PROCESSO
	static {
		try {
			// Carregar Chave Pública (usada pelo Device)
			try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE))) {
				edgePublicKey = (PublicKey) ois.readObject();
			}
			// Carregar Chave Privada (usada pelo EdgeService)
			try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE))) {
				edgePrivateKey = (PrivateKey) ois.readObject();
			}
			System.out.println("✅ SecurityUtils: Par de chaves RSA carregado do disco com sucesso.");
		} catch (FileNotFoundException e) {
			System.err.println("❌ ERRO CRÍTICO: Arquivo de chave não encontrado. Execute KeyGeneratorMain primeiro.");
			// Impede a execução se as chaves não estiverem no lugar
			throw new RuntimeException("Chaves não encontradas, impossível continuar.", e);
		} catch (Exception e) {
			System.err.println("❌ Erro ao carregar chaves RSA: " + e.getMessage());
			throw new RuntimeException("Falha na desserialização da chave.", e);
		}
	}

	// --- Métodos getEdgePublicKey() e getEdgePrivateKey() permanecem os mesmos ---
	public static PublicKey getEdgePublicKey() {
		return edgePublicKey;
	}

	public static PrivateKey getEdgePrivateKey() {
		return edgePrivateKey;
	}


	// 1. Geração de Chave Simétrica (AES) - Usada pelo Dispositivo
	public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256); // Tamanho da chave
		return keyGen.generateKey();
	}

	// 2. Criptografia Assimétrica para Chave (RSA) - Usada pelo Dispositivo
	public static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey targetPublicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, targetPublicKey);
		return cipher.doFinal(symmetricKey.getEncoded());
	}

	// 3. Descriptografia Assimétrica da Chave (RSA) - Usada pela Borda
	public static SecretKey decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedKeyBytes = cipher.doFinal(encryptedSymmetricKey);
		// Recria o objeto SecretKey a partir dos bytes descriptografados
		return new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
	}

	// 4. Criptografia Simétrica para Dados (AES) - Usada pelo Dispositivo
	public static byte[] encryptData(String data, SecretKey symmetricKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
		return cipher.doFinal(data.getBytes());
	}

	// 5. Descriptografia Simétrica dos Dados (AES) - Usada pela Borda
	public static String decryptData(byte[] encryptedData, SecretKey symmetricKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
		byte[] decryptedBytes = cipher.doFinal(encryptedData);
		return new String(decryptedBytes);
	}
}