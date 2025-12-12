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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import server.security.CryptoManager;

public class EdgeService {

	// ============================================================
	// 1. CONFIGURAÇÕES GERAIS
	// ============================================================
	public static final String BORDER_ADDRESS = "127.0.0.1";
	public static final String DC_ADDRESS = "127.0.0.1";

	public static final int EDGE_PORT = 8081;
	public static final int DC_PORT = 8082;

	private static final String EDGE_BD_FILE = "border_db.txt";
	private static final int MAX_CACHE_SIZE = 50;

	private static PublicKey edgePublicKey;
	private static PrivateKey edgePrivateKey;

	private final ConcurrentHashMap<String, SecretKey> activeKeys = new ConcurrentHashMap<>();

	private static final Set<String> blockedDevices = ConcurrentHashMap.newKeySet();

	Map<String, String> devicePasswords = new HashMap<>();

	public static final int EDGE_CONTROL_PORT = 9099;

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

			System.out.println("[OK] Par de chaves RSA do Edge gerado com sucesso.");
		} catch (Exception e) {
			throw new RuntimeException("Erro ao gerar par RSA do Edge", e);
		}
	}

	// ============================================================
	// 2. INICIALIZAÇÃO DO EDGE
	// ============================================================
	public void start() {
		System.out.printf("[INFO] EdgeService iniciado na porta %d...%n", EDGE_PORT);

		try {
			loadPasswords("device_credentials.txt");
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {
			ensureConnected();
		} catch (Exception e) {
			System.err.println("[AVISO] DC indisponível na inicialização: " + e.getMessage());
		}

		new Thread(this::startControlChannel).start();

		new Thread(this::startUDPListener).start();

		startMainTCPListener();
	}

	private void startMainTCPListener() {
		try (ServerSocket serverSocket = new ServerSocket(EDGE_PORT)) {
			while (true) {
				Socket clientSocket = serverSocket.accept();
				new Thread(() -> handleTCPKeyExchange(clientSocket)).start();
			}
		} catch (Exception e) {
			System.err.println("[ERRO] EdgeService TCP caiu: " + e.getMessage());
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
			System.out.println("[OK] Conexão com DataCenter OK + Handshake AES.");
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
			System.err.println("[AVISO] Erro ao enviar. Tentando reconectar: " + first.getMessage());
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
	// 4. TROCA DE CHAVES E ID (TCP)
	// ============================================================
	private void handleTCPKeyExchange(Socket socket) {
		SecretKey symmetricKey = null;
		String deviceId = "UNKNOWN";

		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			if (!"REQUEST_PUB_KEY".equals(in.readLine())) {
				out.println("ERROR: Missing REQUEST_PUB_KEY");
				return;
			}

			String pubKeyB64 = Base64.getEncoder().encodeToString(edgePublicKey.getEncoded());
			out.println("EDGE_PUB_KEY:" + pubKeyB64);

			byte[] encryptedSymKey = Base64.getDecoder().decode(in.readLine());
			symmetricKey = CryptoManager.decryptSymmetricKey(encryptedSymKey, edgePrivateKey);

			out.println("KEY_EXCHANGE_SUCCESS");

			String idLine = in.readLine();
			if (idLine == null || !idLine.startsWith("DEVICE_ID:")) {
				out.println("ERROR: Missing DEVICE_ID");
				return;
			}
			deviceId = idLine.substring(10);

			String hmacLine = in.readLine();
			if (hmacLine == null || !hmacLine.startsWith("HMAC:")) {
				out.println("ERROR: Missing HMAC");
				return;
			}
			String receivedHmac = hmacLine.substring(5);

			String password = devicePasswords.get(deviceId);
			if (password == null) {
				System.err.println("[ERRO] Device desconhecido.");
				out.println("AUTH_DENIED");
				return;
			}

			String expected = CryptoManager.hmacSHA256(deviceId, password);

			if (!expected.equals(receivedHmac)) {
				System.err.println("[ERRO] HMAC inválido para " + deviceId);
				out.println("AUTH_DENIED");
				return;
			}

			activeKeys.put(deviceId, symmetricKey);
			System.out.printf("[INFO] Chave AES salva para [%s]\n", deviceId);

			out.println("AUTH_SUCCESS");

			System.out.printf("[INFO] Monitoramento de firewall ativo para [%s]\n", deviceId);

		} catch (Exception e) {
			System.err.println("[ERRO] Erro key-exchange: " + e.getMessage());
		}
	}

	public void loadPasswords(String path) throws IOException {
		List<String> lines = Files.readAllLines(Paths.get(path));
		for (String line : lines) {
			String[] parts = line.split(":");
			devicePasswords.put(parts[0], parts[1]);
		}
	}

	// ============================================================
	// 5. RECEBIMENTO DE DADOS (UDP)
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
			System.err.println("[ERRO] Erro no UDP Listener: " + e.getMessage());
		}
	}

	private void handleUDPData(DatagramPacket packet) {

		try {
			String payload = new String(packet.getData(), 0, packet.getLength(), "UTF-8");
			String[] parts = payload.split("\\|", 2);

			if (parts.length != 2)
				return;

			String deviceId = parts[0];

			if (EdgeService.isBlocked(deviceId)) {
				System.err.println("[WARNING] Pacote ignorado de dispositivo bloqueado: " + deviceId);
				return;
			}

			String encryptedB64 = parts[1];

			SecretKey key = activeKeys.get(deviceId);
			if (key == null) {
				System.err.println("[ERRO] ID desconhecido no UDP: " + deviceId);
				return;
			}

			String decrypted = CryptoManager.decryptAES(Base64.getDecoder().decode(encryptedB64), key);

			System.out.printf("[INFO] (UDP) [%s] => %s\n", deviceId, decrypted);

			saveDataToCache(deviceId, decrypted);
			sendData(decrypted);

		} catch (Exception e) {
			System.err.println("[ERRO] Erro processando UDP: " + e.getMessage());
		}
	}

	// ============================================================
	// 6. CACHE FIFO
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

			System.out.printf("[INFO] Cache atualizado (%d itens)\n", lines.size());

		} catch (IOException e) {
			System.err.println("[ERRO] Erro no cache: " + e.getMessage());
		}
	}

	// ============================================================
	// 8. FIREWALL
	// ============================================================

	private void startControlChannel() {
		System.out.println("[EDGE] Controle administrativo escutando na porta " + EDGE_CONTROL_PORT);

		try (ServerSocket server = new ServerSocket(EDGE_CONTROL_PORT)) {
			while (true) {
				Socket socket = server.accept();
				new Thread(() -> handleControlCommand(socket)).start();
			}
		} catch (Exception e) {
			System.err.println("[ERRO] Controle administrativo caiu: " + e.getMessage());
		}
	}

	private void handleControlCommand(Socket socket) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
			String line = in.readLine();

			if (line == null)
				return;

			if (line.startsWith("BLOCK:")) {
				String device = line.substring(6);
				blockedDevices.add(device);
				System.out.println("[EDGE] >>> Dispositivo BLOQUEADO via canal administrativo: " + device);
			}

		} catch (Exception e) {
			System.err.println("[ERRO] Controle administrativo: " + e.getMessage());
		}
	}

	public static boolean isBlocked(String deviceId) {
		return blockedDevices.contains(deviceId);
	}

	// ============================================================
	// 8. MAIN
	// ============================================================
	public static void main(String[] args) {
		System.out.println("--- [INFO] INICIANDO EDGE ---");
		new EdgeService().start();
	}
}
