package server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import security.SecurityUtils;

public class EdgeService {

	public static final String BORDER_ADDRESS = "127.0.0.1";
	public static final int EDGE_PORT = 8081;
	private static final String EDGE_BD_FILE = "border_db.txt";
	private static final int MAX_CACHE_SIZE = 50;
	private final ConcurrentHashMap<String, SecretKey> activeKeys = new ConcurrentHashMap<>();

	public void start() {
		System.out.printf("💻 EdgeService iniciado na porta %d...%n", EDGE_PORT);

		// 1. Inicia o listener UDP em uma nova Thread
		new Thread(() -> this.startUDPListener()).start();

		// 2. Continua o listener TCP (para Chaves/ID) na thread principal
		try (ServerSocket serverSocket = new ServerSocket(EDGE_PORT)) {
			while (true) {
				Socket clientSocket = serverSocket.accept();
				// Usa uma thread para lidar com a fase TCP (curta duração)
				new Thread(() -> handleTCPKeyExchange(clientSocket)).start();
			}
		} catch (Exception e) {
			System.err.println("❌ EdgeService parou inesperadamente: " + e.getMessage());
		}
	}

	private void startUDPListener() {
		// Usa a mesma porta do TCP para simplicidade, mas um cenário real usaria portas
		// diferentes
		try (DatagramSocket udpSocket = new DatagramSocket(EDGE_PORT)) {
			byte[] buffer = new byte[2048]; // Buffer grande para o pacote Base64
			System.out.println("UDP: Listener ativo na porta " + EDGE_PORT);

			while (true) {
				DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
				udpSocket.receive(packet);

				// Processa o pacote UDP em uma thread, se a lógica for pesada,
				// mas para este caso, processamos diretamente para evitar sobrecarga de
				// threads.
				handleUDPData(packet);
			}
		} catch (Exception e) {
			System.err.println("❌ Erro no listener UDP: " + e.getMessage());
		}
	}

	// --- NOVO MÉTODO: Processamento de Dados UDP ---
	private void handleUDPData(DatagramPacket packet) {
		try {
			// Recebemos a string: "ID|Base64_Criptografada"
			String fullPayload = new String(packet.getData(), 0, packet.getLength(), "UTF-8");

			String[] parts = fullPayload.split("\\|", 2);
			if (parts.length != 2) {
				System.out.println("❌ EdgeService: (UDP) Pacote malformado recebido.");
				return;
			}

			String clientDeviceId = parts[0];
			String encryptedDataB64 = parts[1];

			SecretKey symmetricKey = activeKeys.get(clientDeviceId);

			if (symmetricKey == null) {
				System.out.printf("❌ EdgeService: (UDP) ID %s desconhecido ou chave não armazenada. Ignorando.\n",
						clientDeviceId);
				return;
			}

			// 2. Descriptografia usando a chave correta
			byte[] encryptedData = Base64.getDecoder().decode(encryptedDataB64);
			String decryptedData = SecurityUtils.decryptData(encryptedData, symmetricKey);

			// Se chegou aqui, funcionou
			System.out.printf("🟢 EdgeService: (UDP) [%s] Dado Descriptografado recebido: %s\n", clientDeviceId,
					decryptedData);
			saveDataToCache(clientDeviceId, decryptedData);

		} catch (Exception e) {
			System.err.println("❌ Erro no processamento UDP: " + e.getMessage());
		}
	}

	// --- MÉTODO EXISTENTE: TCP para Troca de Chaves/ID (handleTCPKeyExchange) ---
	private void handleTCPKeyExchange(Socket socket) {
		SecretKey symmetricKey = null;
		String clientDeviceId = "UNKNOWN";

		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);) {

			// ... (Lógica de Troca de Chaves RSA mantida) ...

			String encryptedKeyData = in.readLine();
			if (encryptedKeyData == null)
				return;
			// ... (Descriptografia da Chave RSA mantida) ...

			byte[] encryptedSymmetricKey = Base64.getDecoder().decode(encryptedKeyData);
			PrivateKey edgePrivateKey = SecurityUtils.getEdgePrivateKey();
			symmetricKey = SecurityUtils.decryptSymmetricKey(encryptedSymmetricKey, edgePrivateKey);

			out.println("KEY_EXCHANGE_SUCCESS");

			// --- RECEBIMENTO DO ID DO DISPOSITIVO ---
			String idLine = in.readLine();
			if (idLine != null && idLine.startsWith("DEVICE_ID:")) {
				clientDeviceId = idLine.substring(10);
			}

			// CRÍTICO: Armazena a chave simétrica para uso no listener UDP
			if (symmetricKey != null) {
				activeKeys.put(clientDeviceId, symmetricKey);
				System.out.printf("🔑 EdgeService: Chave Simétrica [%s] armazenada para uso UDP.\n", clientDeviceId);
			}

			// A conexão TCP se encerra após a troca de chaves e ID.

		} catch (Exception e) {
			System.err.println("❌ Erro no EdgeService (TCP Exchange): " + e.getMessage());
		}
	}

	public static boolean authenticateDevice(String deviceId, String password) {
		// ... (Lógica de autenticação mantida do código anterior) ...
		try (Scanner scanner = new Scanner(new File(SecurityUtils.CREDENTIALS_FILE))) {
			int count = 0;
			while (scanner.hasNextLine() && count < 4) { // Verifica apenas os 4 primeiros
				String line = scanner.nextLine();
				if (line.trim().isEmpty())
					continue;
				String[] parts = line.split(":");

				if (parts.length == 2 && parts[0].equals(deviceId) && parts[1].equals(password)) {
					System.out.println("✅ SecurityUtils: Autenticação bem-sucedida para o Dispositivo " + deviceId);
					return true;
				}
				count++;
			}
		} catch (FileNotFoundException e) {
			System.err.println(
					"❌ SecurityUtils: Arquivo de credenciais não encontrado: " + SecurityUtils.CREDENTIALS_FILE);
			return false;
		}
		System.err.println("❌ SecurityUtils: Falha na autenticação para o Dispositivo " + deviceId);
		return false;
	}

	/**
	 * Adiciona um novo dado ao cache (arquivo TXT), garantindo o limite FIFO.
	 */
	private synchronized void saveDataToCache(String deviceId, String decryptedData) {
		String dataToSave = String.format("[%s] %s", deviceId, decryptedData);

		try {
			File cache = new File(EDGE_BD_FILE);
			// 1. LER TODAS AS LINHAS
			// Usamos uma lista para manipular as linhas eficientemente
			java.util.List<String> lines = new java.util.ArrayList<>();
			if (cache.exists()) {
				try (Scanner scanner = new Scanner(cache)) {
					while (scanner.hasNextLine()) {
						lines.add(scanner.nextLine());
					}
				}
			}

			// 2. IMPLEMENTAR FIFO (se o tamanho máximo for atingido)
			if (lines.size() >= MAX_CACHE_SIZE) {
				lines.remove(0); // Remove o elemento mais antigo (primeiro da lista)
				System.out.printf("🗑️ Borda Cache: Limite de %d atingido. Removido o dado mais antigo.\n",
						MAX_CACHE_SIZE);
			}

			// 3. ADICIONAR O NOVO DADO
			lines.add(dataToSave);

			// 4. ESCREVER TODAS AS LINHAS DE VOLTA NO ARQUIVO
			try (PrintWriter writer = new PrintWriter(new FileWriter(EDGE_BD_FILE, false))) { // false = sobrescrever
				for (String line : lines) {
					writer.println(line);
				}
			}
			System.out.printf("💾 Borda Cache: Novo dado salvo. Tamanho atual: %d\n", lines.size());

		} catch (IOException e) {
			System.err.println("❌ Erro ao manipular o arquivo de cache: " + e.getMessage());
		}
	}

	public static void main(String[] args) {
		System.out.println("--- 🚀 INICIANDO PROCESSO DO SERVIDOR DE BORDA (EDGE) ---");
		EdgeService edge = new EdgeService();
		// Chama start() na thread principal do processo Edge
		edge.start();
	}
}