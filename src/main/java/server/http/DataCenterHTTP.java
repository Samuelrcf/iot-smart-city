package server.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import server.security.CryptoManager;

public class DataCenterHTTP {

	// ============================
	// CONFIGURAÇÕES
	// ============================
	private static final int PORT = 7000;

	private final KeyPair dcKeyPair;
	private HttpServer server;

	// ============================
	// CONEXÃO COM O DB
	// ============================
	private Socket dbSocket;
	private PrintWriter dbOut;
	private BufferedReader dbIn;
	private SecretKey dbAESKey;
	private PublicKey dbPublicKey;

	// ============================
	// CHAVES AES DE CLIENTES
	// ============================
	private final ConcurrentHashMap<String, SecretKey> clientKeys = new ConcurrentHashMap<>();

	// ============================
	// CONSTRUTOR
	// ============================
	public DataCenterHTTP() throws Exception {
		this.dcKeyPair = generateRSAKeyPair();
	}

	public PublicKey getPublicKey() {
		return this.dcKeyPair.getPublic();
	}

	// ============================
	// INICIALIZAÇÃO DO SERVIDOR HTTP
	// ============================
	public void start() throws Exception {
		connectToDatabase();

		server = HttpServer.create(new InetSocketAddress(PORT), 0);

		registerEndpoints();

		server.setExecutor(null);
		server.start();

		System.out.println("🌐 DataCenter HTTP iniciado na porta " + PORT);
	}

	private void registerEndpoints() {
		server.createContext("/publickey", this::handlePublicKey);
		server.createContext("/auth", this::handleAuthHandshake);

		server.createContext("/dados", exchange -> handleProtectedRequest(exchange, "GET_DATA"));
		server.createContext("/relatorios", exchange -> handleProtectedRequest(exchange, "GET_REPORT"));
		server.createContext("/alertas", exchange -> handleProtectedRequest(exchange, "GET_ALERTS"));
		server.createContext("/previsoes", exchange -> handleProtectedRequest(exchange, "GET_FORECAST"));
	}

	// =========================================================
	// 1. ENDPOINT DE ENVIO DA CHAVE PÚBLICA RSA
	// =========================================================
	private void handlePublicKey(HttpExchange exchange) throws IOException {
		if (!exchange.getRequestMethod().equals("GET")) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}

		byte[] response = Base64.getEncoder().encode(getPublicKey().getEncoded());

		exchange.sendResponseHeaders(200, response.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(response);
		}
	}

	// =========================================================
	// 2. HANDSHAKE DO CLIENTE COM AES
	// =========================================================
	private void handleAuthHandshake(HttpExchange exchange) throws IOException {
		if (!exchange.getRequestMethod().equals("POST")) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}

		String clientId = exchange.getRequestHeaders().getFirst("Client-ID");
		if (clientId == null) {
			exchange.sendResponseHeaders(400, -1);
			return;
		}

		String encryptedKeyB64 = new String(exchange.getRequestBody().readAllBytes());
		byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKeyB64);

		try {
			Cipher rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.DECRYPT_MODE, dcKeyPair.getPrivate());

			byte[] aesBytes = rsa.doFinal(encryptedKeyBytes);
			SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");

			clientKeys.put(clientId, aesKey);

			exchange.sendResponseHeaders(200, -1);

		} catch (Exception e) {
			exchange.sendResponseHeaders(500, -1);
		}
	}

	// =========================================================
	// 3. ENDPOINTS PROTEGIDOS POR AES (CLIENTE)
	// =========================================================
	private void handleProtectedRequest(HttpExchange exchange, String command) throws IOException {
		String response = requestFromDB(command);
		sendEncryptedResponse(exchange, response);
	}

	// =========================================================
	// 4. ENVIO DE RESPOSTA CRIPTOGRAFADA COM CHAVE AES DO CLIENTE
	// =========================================================
	private void sendEncryptedResponse(HttpExchange exchange, String message) throws IOException {
		String clientId = exchange.getRequestHeaders().getFirst("Client-ID");

		if (clientId == null || !clientKeys.containsKey(clientId)) {
			exchange.sendResponseHeaders(403, -1);
			return;
		}

		SecretKey aesKey = clientKeys.get(clientId);

		try {
			Cipher aes = Cipher.getInstance("AES");
			aes.init(Cipher.ENCRYPT_MODE, aesKey);

			byte[] encrypted = aes.doFinal(message.getBytes());
			byte[] b64 = Base64.getEncoder().encode(encrypted);

			exchange.sendResponseHeaders(200, b64.length);

			try (OutputStream os = exchange.getResponseBody()) {
				os.write(b64);
			}

		} catch (Exception e) {
			exchange.sendResponseHeaders(500, -1);
		}
	}

	// =========================================================
	// 5. HANDSHAKE E CONSULTAS AO DB INTERNO
	// =========================================================
	private void connectToDatabase() {
		try {
			dbSocket = new Socket("localhost", 9091);
			dbOut = new PrintWriter(dbSocket.getOutputStream(), true);
			dbIn = new BufferedReader(new InputStreamReader(dbSocket.getInputStream()));

			requestDbPublicKey();
			sendAESKeyToDB();
			validateDbAck();

			System.out.println("🔗 DataCenter HTTP conectado ao DB com criptografia AES.");

		} catch (Exception e) {
			System.err.println("❌ Falha ao conectar ao DB: " + e.getMessage());
		}
	}

	private void requestDbPublicKey() throws Exception {
		dbOut.println("REQUEST_PUB_KEY");

		String line = dbIn.readLine(); // exemplo: PUB_KEY_B64:xxxx
		String keyB64 = line.split(":", 2)[1];

		dbPublicKey = CryptoManager.reconstructPublicKey(keyB64);
	}

	private void sendAESKeyToDB() throws Exception {
		dbAESKey = CryptoManager.generateAESKey();

		byte[] encryptedAES = CryptoManager.encryptSymmetricKey(dbAESKey, dbPublicKey);
		dbOut.println("AES_KEY_B64:" + Base64.getEncoder().encodeToString(encryptedAES));
	}

	private void validateDbAck() throws Exception {
		String ack = dbIn.readLine();
		if (!"KEY_EXCHANGE_SUCCESS".equals(ack)) {
			throw new RuntimeException("Handshake com DB falhou.");
		}
	}

	private String requestFromDB(String command) {
		try {
			byte[] encryptedCmd = CryptoManager.encryptAES(command, dbAESKey);
			dbOut.println(Base64.getEncoder().encodeToString(encryptedCmd));

			String responseB64 = dbIn.readLine();
			byte[] respBytes = Base64.getDecoder().decode(responseB64);

			return CryptoManager.decryptAES(respBytes, dbAESKey);

		} catch (Exception e) {
			return "Erro consultando DB: " + e.getMessage();
		}
	}

	// =========================================================
	// 6. UTILITÁRIOS
	// =========================================================
	private KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		return gen.generateKeyPair();
	}
}
