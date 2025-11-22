package server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import server.security.CryptoManager;

public class EdgeService {

	// ============================================================
	// 1. CONFIGURAÇÕES GERAIS
	// ============================================================
	public static final String BORDER_ADDRESS = "127.0.0.1";
	public static final String DC_ADDRESS = "127.0.0.1";

	public static final int EDGE_PORT = 8081; // Dados TCP/UDP da borda
	public static final int AUTH_PORT = 8080; // Autenticação
	public static final int DC_PORT = 8082; // Porta DataCenter

	private static final String EDGE_BD_FILE = "border_db.txt";
	private static final int MAX_CACHE_SIZE = 50;

	private static PublicKey edgePublicKey;
	private static PrivateKey edgePrivateKey;

	private final ConcurrentHashMap<String, SecretKey> activeKeys = new ConcurrentHashMap<>();

	// Estado da conexão com DataCenter
	private Socket dcSocket;
	private PrintWriter out;
	private BufferedReader in;
	private SecretKey symmetricKey;

	public EdgeService() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair pair = kpg.generateKeyPair();

			edgePublicKey = pair.getPublic();
			edgePrivateKey = pair.getPrivate();

			System.out.println("🔐 Par de chaves RSA do Edge gerado com sucesso.");
		} catch (Exception e) {
			throw new RuntimeException("Erro ao gerar par RSA do Edge", e);
		}
	}

	// ============================================================
	// 2. INICIALIZAÇÃO DO EDGE
	// ============================================================
	public void start() {
		System.out.printf("💻 EdgeService iniciado na porta %d...%n", EDGE_PORT);

		try {
			ensureConnected();
		} catch (Exception e) {
			System.err.println("⚠️ DC indisponível na inicialização: " + e.getMessage());
		}

		// Listeners paralelos
		new Thread(this::startUDPListener).start();
		new Thread(this::startAuthListener).start();

		// Listener principal TCP (troca de chaves + ID)
		startMainTCPListener();
	}

	private void startMainTCPListener() {
		try (ServerSocket serverSocket = new ServerSocket(EDGE_PORT)) {
			while (true) {
				Socket clientSocket = serverSocket.accept();
				new Thread(() -> handleTCPKeyExchange(clientSocket)).start();
			}
		} catch (Exception e) {
			System.err.println("❌ EdgeService TCP caiu: " + e.getMessage());
		}
	}

	// ============================================================
	// 3. CONEXÃO COM DATA CENTER + HANDSHAKE AES
	// ============================================================
	private synchronized void ensureConnected() throws Exception {
		if (dcSocket != null && !dcSocket.isClosed() && out != null && in != null && symmetricKey != null)
			return;

		closeDcConnection();

		try {
			connectToDataCenter();
			System.out.println("🔗 Conexão com DataCenter OK + Handshake AES.");
		} catch (Exception e) {
			closeDcConnection();
			throw e;
		}
	}

	private synchronized void closeDcConnection() {
		try {
			if (out != null)
				out.flush();
		} catch (Exception ignore) {
		}
		try {
			if (in != null)
				in.close();
		} catch (Exception ignore) {
		}
		try {
			if (out != null)
				out.close();
		} catch (Exception ignore) {
		}
		try {
			if (dcSocket != null && !dcSocket.isClosed())
				dcSocket.close();
		} catch (Exception ignore) {
		}

		in = null;
		out = null;
		dcSocket = null;
		symmetricKey = null;
	}

	private void connectToDataCenter() throws Exception {
		dcSocket = new Socket(DC_ADDRESS, DC_PORT);
		out = new PrintWriter(dcSocket.getOutputStream(), true);
		in = new BufferedReader(new InputStreamReader(dcSocket.getInputStream()));
		performHandshake();
	}

	private void performHandshake() throws Exception {
		out.println("REQUEST_PUB_KEY");

		String pubKeyLine = in.readLine();
		PublicKey dcPublicKey = CryptoManager.reconstructPublicKey(pubKeyLine.substring(12));

		SecretKey sessionKey = CryptoManager.generateAESKey();
		byte[] encryptedKey = CryptoManager.encryptSymmetricKey(sessionKey, dcPublicKey);

		out.println("AES_KEY_B64:" + Base64.getEncoder().encodeToString(encryptedKey));

		if (!"KEY_EXCHANGE_SUCCESS".equals(in.readLine()))
			throw new RuntimeException("Handshake DC falhou");

		symmetricKey = sessionKey;
	}

	public synchronized void sendData(String data) throws Exception {
		try {
			ensureConnected();
			sendEncryptedToDC(data);
		} catch (Exception first) {
			System.err.println("⚠️ Erro ao enviar. Tentando reconectar: " + first.getMessage());
			closeDcConnection();
			ensureConnected();
			sendEncryptedToDC(data);
		}
	}

	private void sendEncryptedToDC(String data) throws Exception {
		byte[] encrypted = CryptoManager.encryptAES(data, symmetricKey);
		out.println(Base64.getEncoder().encodeToString(encrypted));

		String ack = in.readLine();
		if (!"DC_ACK".equals(ack))
			throw new IOException("ACK inválido: " + ack);
	}

	// ============================================================
	// 4. AUTENTICAÇÃO DE DISPOSITIVOS
	// ============================================================
	public void startAuthListener() {
		System.out.printf("🔑 AuthService (Edge) iniciado na porta %d...%n", AUTH_PORT);
		try (ServerSocket authSocket = new ServerSocket(AUTH_PORT)) {
			while (true) {
				Socket s = authSocket.accept();
				new Thread(() -> handleAuthRequestEdge(s)).start();
			}
		} catch (Exception e) {
			System.err.println("❌ AuthService caiu: " + e.getMessage());
		}
	}

	private void handleAuthRequestEdge(Socket socket) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			String line = in.readLine();
			if (line == null || !line.startsWith("CRED:")) {
				out.println("AUTH_FAIL: Invalid request.");
				return;
			}

			String[] parts = line.substring(5).split(":");
			if (parts.length != 2) {
				out.println("AUTH_FAIL: Malformed credentials.");
				return;
			}

			String deviceId = parts[0];
			String password = parts[1];

			if (authenticateDevice(deviceId, password)) {
				String edgeAddress = BORDER_ADDRESS + ":" + EDGE_PORT;
				out.println("AUTH_SUCCESS:" + edgeAddress);
				System.out.println("🔑 Dispositivo " + deviceId + " autenticado.");
			} else {
				out.println("AUTH_FAIL: Invalid credentials.");
			}

		} catch (Exception e) {
			System.err.println("❌ Auth Error: " + e.getMessage());
		}
	}

	// ============================================================
	// 5. TROCA DE CHAVES E ID (TCP)
	// ============================================================
	private void handleTCPKeyExchange(Socket socket) {
		SecretKey symmetricKey = null;
		String deviceId = "UNKNOWN";

		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			// Solicitação inicial
			if (!"REQUEST_PUB_KEY".equals(in.readLine())) {
				out.println("ERROR: Missing REQUEST_PUB_KEY");
				return;
			}

			// Envia a chave pública do Edge gerada no construtor
			String pubKeyB64 = Base64.getEncoder().encodeToString(edgePublicKey.getEncoded());
			out.println("EDGE_PUB_KEY:" + pubKeyB64);

			// Recebe chave AES cifrada
			byte[] encryptedSymKey = Base64.getDecoder().decode(in.readLine());

			// 🔐 Agora usa a chave privada interna do Edge
			symmetricKey = CryptoManager.decryptSymmetricKey(encryptedSymKey, edgePrivateKey);

			out.println("KEY_EXCHANGE_SUCCESS");

			// Recebe ID do dispositivo
			String idLine = in.readLine();
			if (idLine != null && idLine.startsWith("DEVICE_ID:")) {
				deviceId = idLine.substring(10);
			}

			// Armazena chave AES ativa
			activeKeys.put(deviceId, symmetricKey);
			System.out.printf("🔑 Chave AES salva para [%s]\n", deviceId);

		} catch (Exception e) {
			System.err.println("❌ Erro key-exchange: " + e.getMessage());
		}
	}

	// ============================================================
	// 6. RECEBIMENTO DE DADOS (UDP)
	// ============================================================
	private void startUDPListener() {
		try (DatagramSocket udp = new DatagramSocket(EDGE_PORT)) {
			byte[] buffer = new byte[2048];

			while (true) {
				DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
				udp.receive(packet);
				handleUDPData(packet);
			}

		} catch (Exception e) {
			System.err.println("❌ Erro no UDP Listener: " + e.getMessage());
		}
	}

	private void handleUDPData(DatagramPacket packet) {
		try {
			String payload = new String(packet.getData(), 0, packet.getLength(), "UTF-8");
			String[] parts = payload.split("\\|", 2);

			if (parts.length != 2)
				return;

			String deviceId = parts[0];
			String encryptedB64 = parts[1];

			SecretKey key = activeKeys.get(deviceId);
			if (key == null) {
				System.err.println("❌ ID desconhecido no UDP: " + deviceId);
				return;
			}

			String decrypted = CryptoManager.decryptAES(Base64.getDecoder().decode(encryptedB64), key);

			System.out.printf("🟢 (UDP) [%s] => %s\n", deviceId, decrypted);
			saveDataToCache(deviceId, decrypted);
			sendData(decrypted);

		} catch (Exception e) {
			System.err.println("❌ Erro processando UDP: " + e.getMessage());
		}
	}

	// ============================================================
	// 7. CACHE FIFO
	// ============================================================
	private synchronized void saveDataToCache(String deviceId, String decryptedData) {
		String entry = "[" + deviceId + "] " + decryptedData;

		try {
			File file = new File(EDGE_BD_FILE);
			List<String> lines = new ArrayList<>();

			if (file.exists()) {
				try (Scanner scan = new Scanner(file)) {
					while (scan.hasNextLine())
						lines.add(scan.nextLine());
				}
			}

			if (lines.size() >= MAX_CACHE_SIZE)
				lines.remove(0);
			lines.add(entry);

			try (PrintWriter w = new PrintWriter(new FileWriter(EDGE_BD_FILE))) {
				for (String l : lines)
					w.println(l);
			}

			System.out.printf("💾 Cache atualizado (%d itens)\n", lines.size());

		} catch (IOException e) {
			System.err.println("❌ Erro no cache: " + e.getMessage());
		}
	}

	// ============================================================
	// 8. AUTENTICAÇÃO
	// ============================================================
	public static boolean authenticateDevice(String deviceId, String password) {
		try (Scanner scan = new Scanner(new File(CryptoManager.CREDENTIALS_FILE))) {
			int count = 0;
			while (scan.hasNextLine() && count < 4) {
				String line = scan.nextLine();
				if (line.trim().isEmpty())
					continue;

				String[] parts = line.split(":");
				if (parts.length == 2 && parts[0].equals(deviceId) && parts[1].equals(password)) {
					System.out.println("✅ Autenticação OK para " + deviceId);
					return true;
				}
				count++;
			}
		} catch (Exception e) {
			System.err.println("❌ Credenciais não encontradas.");
			return false;
		}
		return false;
	}

	// ============================================================
	// 9. MAIN
	// ============================================================
	public static void main(String[] args) {

		System.out.println("--- 🚀 INICIANDO EDGE ---");
		new EdgeService().start();
	}
}
