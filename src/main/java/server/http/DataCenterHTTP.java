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
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import server.security.CryptoManager;

public class DataCenterHTTP {

	// ============================
	// CONFIGURAÇÕES
	// ============================
	private static final int PORT = 7000;

	private final KeyPair dcKeyPair;
	private HttpServer server;

	private final Map<String, String> validUsers = Map.of("samuel", "12345");

	private static final String JWT_SECRET = "qwerasdfzxcv1234qwerasdfzxcv1234";

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

		System.out.println("[INFO] DataCenter HTTP iniciado na porta " + PORT);
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
		if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}

		// read body (Base64)
		String encryptedB64 = new String(exchange.getRequestBody().readAllBytes(), "UTF-8");
		if (encryptedB64 == null || encryptedB64.isBlank()) {
			exchange.sendResponseHeaders(400, -1);
			return;
		}

		try {
			byte[] encrypted = Base64.getDecoder().decode(encryptedB64);

			Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			rsa.init(Cipher.DECRYPT_MODE, dcKeyPair.getPrivate());
			byte[] plain = rsa.doFinal(encrypted);

			String payload = new String(plain, "UTF-8");
			String user = null, pass = null, aesB64 = null;
			for (String line : payload.split("\n")) {
				if (line.startsWith("USER="))
					user = line.substring(5).trim();
				else if (line.startsWith("PASS="))
					pass = line.substring(5).trim();
				else if (line.startsWith("AES="))
					aesB64 = line.substring(4).trim();
			}

			if (user == null || pass == null || aesB64 == null) {
				exchange.sendResponseHeaders(400, -1);
				return;
			}

			String expectedPass = validUsers.get(user);
			if (expectedPass == null || !expectedPass.equals(pass)) {
				exchange.sendResponseHeaders(403, -1);
				System.err.println("[ERRO] Falha de autenticação para usuário: " + user);
				return;
			}

			byte[] aesBytes = Base64.getDecoder().decode(aesB64);
			SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesBytes, "AES");

			// guarda a chave AES associada ao usuário
			clientKeys.put(user, aesKey);

			// gera JWT e devolve no header Authorization
			String jwt = createJwt(user, 15 * 60); // 15 minutos (ver pergunta anterior)
			exchange.getResponseHeaders().add("Authorization", "Bearer " + jwt);

			exchange.sendResponseHeaders(200, -1);
			System.out.println("[OK] Handshake concluído para usuário: " + user);

		} catch (Exception e) {
			System.err.println("[ERRO] handleAuthHandshake: " + e.getMessage());
			exchange.sendResponseHeaders(500, -1);
		}
	}

	// =========================================================
	// 3. ENDPOINTS PROTEGIDOS POR AES (CLIENTE)
	// =========================================================
	private void handleProtectedRequest(HttpExchange exchange, String command) throws IOException {

		String user = authenticateJwt(exchange);
		if (user == null) {
			exchange.sendResponseHeaders(403, -1);
			return;
		}
		SecretKey aesKey = clientKeys.get(user);
		if (aesKey == null) {
			exchange.sendResponseHeaders(403, -1);
			return;
		}

		String response = requestFromDB(command);
		sendEncryptedResponse(exchange, response, aesKey);
	}

	// =========================================================
	// 4. ENVIO DE RESPOSTA CRIPTOGRAFADA
	// =========================================================
	private void sendEncryptedResponse(HttpExchange exchange, String message, SecretKey aesKey) throws IOException {
		try {
			Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
			aes.init(Cipher.ENCRYPT_MODE, aesKey);

			byte[] encrypted = aes.doFinal(message.getBytes("UTF-8"));
			byte[] b64 = Base64.getEncoder().encode(encrypted);

			exchange.sendResponseHeaders(200, b64.length);
			try (OutputStream os = exchange.getResponseBody()) {
				os.write(b64);
			}
		} catch (Exception e) {
			System.err.println("[ERRO] sendEncryptedResponse: " + e.getMessage());
			exchange.sendResponseHeaders(500, -1);
		}
	}

	// =========================================================
	// 5. HANDSHAKE COM O DB INTERNO
	// =========================================================
	private void connectToDatabase() {
		try {
			dbSocket = new Socket("localhost", 9091);
			dbOut = new PrintWriter(dbSocket.getOutputStream(), true);
			dbIn = new BufferedReader(new InputStreamReader(dbSocket.getInputStream()));

			requestDbPublicKey();
			sendAESKeyToDB();
			validateDbAck();

			System.out.println("[INFO] DataCenter HTTP conectado ao DB com criptografia AES.");

		} catch (Exception e) {
			System.err.println("[ERRO] Falha ao conectar ao DB: " + e.getMessage());
		}
	}

	private void requestDbPublicKey() throws Exception {
		dbOut.println("REQUEST_PUB_KEY");

		String line = dbIn.readLine();
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
			return "[ERRO] Falha consultando DB: " + e.getMessage();
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

	// =========================================================
	// JWT helpers
	// =========================================================

	private String createJwt(String username, long ttlSeconds) {
		long nowMillis = System.currentTimeMillis();

		return Jwts.builder().setSubject(username).setIssuedAt(new Date(nowMillis))
				.setExpiration(new Date(nowMillis + ttlSeconds * 1000))
				.signWith(Keys.hmacShaKeyFor(JWT_SECRET.getBytes()), SignatureAlgorithm.HS256).compact();
	}

	private String validateAndGetSubjectFromJwt(String token) {
		try {
			return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(JWT_SECRET.getBytes())).build()
					.parseClaimsJws(token).getBody().getSubject();
		} catch (Exception e) {
			return null;
		}
	}

	// =========================================================
	// Autenticação com JWT
	// =========================================================
	private String authenticateJwt(HttpExchange exchange) {
		String header = exchange.getRequestHeaders().getFirst("Authorization");
		if (header == null || !header.startsWith("Bearer "))
			return null;
		String token = header.substring(7);
		return validateAndGetSubjectFromJwt(token);
	}

}
