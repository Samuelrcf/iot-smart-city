package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;

import server.db.DataBase;
import server.http.DataCenterHTTP;
import server.security.CryptoManager;

public class DataCenter {

	// ============================
	// CONFIGURAÇÕES DO DATACENTER
	// ============================
	public static final int DC_PORT = 8082;
	public static final String DC_ADDRESS = "127.0.0.1";

	// Chaves utilizadas para o handshake com Edge
	private final KeyPair dcKeyPair;

	// ============================
	// CONEXÃO PERSISTENTE COM O DB
	// ============================
	private Socket dbSocket;
	private PrintWriter dbOut;
	private BufferedReader dbIn;
	private SecretKey dbSymmetricKey;

	// ============================
	// CONSTRUTOR
	// ============================
	public DataCenter() throws NoSuchAlgorithmException {
		this.dcKeyPair = generateRSAKeyPair();
	}

	// ============================
	// INICIALIZAÇÃO DO SERVIDOR
	// ============================
	public void start() {
		System.out.printf("[INFO] DataCenter ativo na porta %d (TCP).%n", DC_PORT);

		try (ServerSocket serverSocket = new ServerSocket(DC_PORT)) {
			while (true) {
				Socket edgeSocket = serverSocket.accept();
				new Thread(() -> handleEdgeConnection(edgeSocket)).start();
			}
		} catch (Exception e) {
			System.err.println("[ERRO] DataCenter falhou: " + e.getMessage());
		}
	}

	// =========================================================
	// 1. HANDSHAKE E COMUNICAÇÃO COM O EDGE SERVICE
	// =========================================================
	private void handleEdgeConnection(Socket socket) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			// ---- HANDSHAKE RSA ----
			if (!"REQUEST_PUB_KEY".equals(in.readLine()))
				return;

			out.println("PUB_KEY_B64:" + Base64.getEncoder().encodeToString(dcKeyPair.getPublic().getEncoded()));

			SecretKey symmetricKey = receiveSymmetricKey(in);

			out.println("KEY_EXCHANGE_SUCCESS");

			// ---- LOOP DE DADOS SIMÉTRICOS ----
			processEncryptedMessages(in, out, symmetricKey);

		} catch (Exception e) {
			System.err.println("[ERRO] Erro no DC: " + e.getMessage());
		}
	}

	private SecretKey receiveSymmetricKey(BufferedReader in) throws Exception {
		String aesLine = in.readLine();
		byte[] encryptedKey = Base64.getDecoder().decode(aesLine.substring(12));

		return CryptoManager.decryptSymmetricKey(encryptedKey, dcKeyPair.getPrivate());
	}

	private void processEncryptedMessages(BufferedReader in, PrintWriter out, SecretKey symKey) throws Exception {
		String encryptedLine;

		while ((encryptedLine = in.readLine()) != null) {
			String decrypted = CryptoManager.decryptAES(Base64.getDecoder().decode(encryptedLine), symKey);

			sendDataToDB(decrypted);

			out.println("DC_ACK");
		}
	}

	// =========================================================
	// 2. MANIPULAÇÃO DA CONEXÃO COM O DB
	// =========================================================
	private synchronized void ensureDbConnected() throws Exception {
		if (dbSocket != null && !dbSocket.isClosed() && dbOut != null && dbIn != null && dbSymmetricKey != null) {
			return;
		}

		closeDbConnection();

		try {
			connectToDatabase();
			System.out.println("[INFO] DataCenter: Conexão com DataBase estabelecida.");
		} catch (Exception e) {
			closeDbConnection();
			throw e;
		}
	}

	private void connectToDatabase() throws Exception {
		dbSocket = new Socket(DC_ADDRESS, DataBase.DB_PORT);
		dbOut = new PrintWriter(dbSocket.getOutputStream(), true);
		dbIn = new BufferedReader(new InputStreamReader(dbSocket.getInputStream()));

		performDbHandshake();
	}

	private void performDbHandshake() throws Exception {
		// 1. solicitar chave pública
		dbOut.println("REQUEST_PUB_KEY");

		String pubKeyLine = dbIn.readLine();
		if (pubKeyLine == null || !pubKeyLine.startsWith("PUB_KEY_B64:")) {
			throw new IOException("Falha ao obter chave pública do DB.");
		}

		PublicKey dbPublicKey = CryptoManager.reconstructPublicKey(pubKeyLine.substring(12));

		// 2. gerar e enviar chave AES
		SecretKey sessionKey = CryptoManager.generateAESKey();
		byte[] encryptedKey = CryptoManager.encryptSymmetricKey(sessionKey, dbPublicKey);

		dbOut.println("AES_KEY_B64:" + Base64.getEncoder().encodeToString(encryptedKey));

		if (!"KEY_EXCHANGE_SUCCESS".equals(dbIn.readLine())) {
			throw new IOException("Handshake com DB falhou.");
		}

		dbSymmetricKey = sessionKey;
	}

	private synchronized void closeDbConnection() {
		try { if (dbOut != null) dbOut.flush(); } catch (Exception ignore) {}
		try { if (dbIn != null) dbIn.close(); } catch (Exception ignore) {}
		try { if (dbOut != null) dbOut.close(); } catch (Exception ignore) {}
		try { if (dbSocket != null && !dbSocket.isClosed()) dbSocket.close(); } catch (Exception ignore) {}

		dbIn = null;
		dbOut = null;
		dbSocket = null;
		dbSymmetricKey = null;
	}

	// =========================================================
	// 3. ENVIO DE DADOS AO DB (AES)
	// =========================================================
	private synchronized void sendDataToDB(String data) {
		try {
			ensureDbConnected();
		} catch (Exception e) {
			System.err.println("[ERRO] DataCenter: Não foi possível conectar ao DB: " + e.getMessage());
			return;
		}

		try {
			// primeira tentativa
			sendEncryptedToDB(data);
		} catch (Exception firstEx) {
			System.err.println("[AVISO] Tentando reconectar ao DB: " + firstEx.getMessage());
			closeDbConnection();

			try {
				ensureDbConnected();
				sendEncryptedToDB(data);
				System.out.println("[OK] Data salvo (retry).");
			} catch (Exception secondEx) {
				System.err.println("[ERRO] Falha após retry: " + secondEx.getMessage());
				closeDbConnection();
			}
		}
	}

	private void sendEncryptedToDB(String data) throws Exception {
		byte[] encrypted = CryptoManager.encryptAES(data, dbSymmetricKey);
		dbOut.println(Base64.getEncoder().encodeToString(encrypted));

		if (!"DB_ACK".equals(dbIn.readLine())) {
			throw new IOException("ACK inválido do DB.");
		}

		System.out.println("[OK] DataCenter: Dado salvo no DB.");
	}

	// =========================================================
	// 4. UTILITÁRIOS
	// =========================================================
	private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		return keyGen.generateKeyPair();
	}

	// =========================================================
	// 5. MAIN
	// =========================================================
	public static void main(String[] args) {
		try {
			DataCenter dc = new DataCenter();

			new Thread(dc::start).start(); // TCP
			new DataCenterHTTP().start(); // HTTP

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
