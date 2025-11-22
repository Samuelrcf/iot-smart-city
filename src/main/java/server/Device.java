package server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Device {

	/*
	 * ============================================================= 1. ATRIBUTOS
	 * =============================================================
	 */
	private final String deviceId;
	private final String password;
	private final Random random = new Random();
	private static long dataIdCounter = 1; // Sequencial para cada dado gerado

	/*
	 * ============================================================= 2. CONSTRUTOR
	 * =============================================================
	 */
	public Device(String deviceId, String password) {
		this.deviceId = deviceId;
		this.password = password;
	}

	/*
	 * ============================================================= 3. CICLO
	 * PRINCIPAL DO DISPOSITIVO
	 * =============================================================
	 */
	public void start() {
		System.out.println("\n--- Dispositivo " + deviceId + " iniciando fluxo... ---");

		String authAddress = discoverService();
		if (authAddress == null)
			return;

		String edgeAddress = authenticate(authAddress);
		if (edgeAddress == null)
			return;

		connectToEdge(edgeAddress);
	}

	/*
	 * ============================================================= 4. DESCOBERTA,
	 * AUTENTICAÇÃO E HANDSHAKE
	 * =============================================================
	 */

	/** 4.1 Descoberta de Serviço */
	private String discoverService() {
		System.out.println("🗺️ Dispositivo: Conectando ao LocationService...");

		try (Socket socket = new Socket(LocationService.LOCATION_ADDRESS, 9000);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

			String response = in.readLine();
			if (response != null && response.startsWith("AUTH_REDIRECT:")) {
				return response.substring(14);
			}

		} catch (Exception e) {
			System.err.println("❌ Dispositivo: Erro na Descoberta: " + e.getMessage());
		}
		return null;
	}

	/** 4.2 Autenticação */
	private String authenticate(String authAddress) {
		String[] parts = authAddress.split(":");
		String host = parts[0];
		int port = Integer.parseInt(parts[1]);

		System.out.println("🔑 Dispositivo: Conectando ao AuthService em " + authAddress + "...");

		try (Socket socket = new Socket(host, port);
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

			out.println("CRED:" + deviceId + ":" + password);

			String response = in.readLine();
			if (response != null && response.startsWith("AUTH_SUCCESS:")) {
				return response.substring(13);
			}

			System.err.println("❌ Dispositivo: Falha na autenticação: " + response);

		} catch (Exception e) {
			System.err.println("❌ Dispositivo: Erro na Autenticação: " + e.getMessage());
		}
		return null;
	}

	/** 4.3 Conexão com Edge (TCP + UDP) */
	private void connectToEdge(String edgeAddress) {
		String[] parts = edgeAddress.split(":");
		String host = parts[0];
		int port = Integer.parseInt(parts[1]);

		System.out.println("💻 Dispositivo: Conectando ao EdgeService em " + edgeAddress + "...");

		SecretKey symmetricKey = null;
		InetAddress edgeAddressUDP = null;

		/*
		 * ----------------------------- FASE 1 — HANDSHAKE TCP
		 * -----------------------------
		 */
		try (Socket socket = new Socket(host, port);
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

			// 1. Solicita chave pública
			out.println("REQUEST_PUB_KEY");

			String line = in.readLine();
			if (line == null || !line.startsWith("EDGE_PUB_KEY:")) {
				throw new Exception("Chave pública não recebida do Edge.");
			}

			// 2. Carrega chave pública
			String pubKeyB64 = line.substring(13);
			byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyB64);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey edgePublicKey = kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

			System.out.println("🔑 Dispositivo: Chave pública recebida do Edge.");

			// 3. Gera chave AES
			symmetricKey = generateAESKey();

			// 4. Envia AES criptografada
			byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, edgePublicKey);
			out.println(Base64.getEncoder().encodeToString(encryptedSymmetricKey));

			if (!"KEY_EXCHANGE_SUCCESS".equals(in.readLine())) {
				throw new Exception("Falha no handshake de chave.");
			}

			System.out.println("🔒 Dispositivo: Troca de chaves concluída.");

			// 5. Envia ID
			out.println("DEVICE_ID:" + deviceId);

			edgeAddressUDP = InetAddress.getByName(host);

		} catch (Exception e) {
			System.err.println("❌ Dispositivo " + deviceId + ": Erro na fase TCP: " + e.getMessage());
			return;
		}

		/*
		 * ----------------------------- FASE 2 — ENVIO UDP
		 * -----------------------------
		 */
		System.out.println("📡 UDP: Iniciando envio de dados climáticos...");

		try (DatagramSocket udpSocket = new DatagramSocket()) {

			long startTime = System.currentTimeMillis();
			long endTime = startTime + (1 * 60 * 1000);

			while (System.currentTimeMillis() < endTime) {

				ClimateData dataObject = generateRandomClimateData();
				String dataString = dataObject.toString();

				// criptografa dados
				byte[] encryptedData = encryptData(dataString, symmetricKey);

				// payload: ID + dados criptografados
				String payload = deviceId + "|" + Base64.getEncoder().encodeToString(encryptedData);
				byte[] dataPacketBytes = payload.getBytes("UTF-8");

				DatagramPacket packet = new DatagramPacket(dataPacketBytes, dataPacketBytes.length, edgeAddressUDP,
						port);

				udpSocket.send(packet);

				System.out.println("[" + deviceId + "] Pacote UDP enviado: " + dataString);

				Thread.sleep(2000 + random.nextInt(1000)); // 2–3s intervalo
			}

			System.out.println("--- Dispositivo " + deviceId + ": Fim do ciclo UDP de 3 minutos. ---");

		} catch (Exception e) {
			System.err.println("❌ Dispositivo " + deviceId + ": Erro na FASE UDP: " + e.getMessage());
		}
	}

	/*
	 * ============================================================= 5. GERAÇÃO DE
	 * DADOS CLIMÁTICOS
	 * =============================================================
	 */
	private ClimateData generateRandomClimateData() {
		double co2 = 350 + (600 - 350) * random.nextDouble();
		double co = 0 + (50 - 0) * random.nextDouble();
		double no2 = 0 + (150 - 0) * random.nextDouble();
		double so2 = 0 + (50 - 0) * random.nextDouble();
		double pm25 = 0 + (200 - 0) * random.nextDouble();
		double pm10 = 0 + (200 - 0) * random.nextDouble();
		double umidade = 30 + (90 - 30) * random.nextDouble();
		double temperatura = 15 + (40 - 15) * random.nextDouble();
		double ruido = 30 + (90 - 30) * random.nextDouble();
		double radiacao = 0 + (10 - 0) * random.nextDouble();

		return new ClimateData(dataIdCounter++, LocalDateTime.now(), co2, co, no2, so2, pm25, pm10, umidade,
				temperatura, ruido, radiacao);
	}

	/*
	 * ============================================================= 6. CRIPTOGRAFIA
	 * =============================================================
	 */
	public SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		return keyGen.generateKey();
	}

	public byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey targetPublicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, targetPublicKey);
		return cipher.doFinal(symmetricKey.getEncoded());
	}

	public static byte[] encryptData(String data, SecretKey symmetricKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
		return cipher.doFinal(data.getBytes());
	}

	/*
	 * ============================================================= 7. EXECUÇÃO
	 * SIMULTÂNEA DOS 5 DISPOSITIVOS
	 * =============================================================
	 */
	public static void main(String[] args) {

		Map<String, String> deviceCredentials = new LinkedHashMap<>();
		deviceCredentials.put("D1", "sensor1");
		deviceCredentials.put("D2", "sensor2");
		deviceCredentials.put("D3", "sensor3");
		deviceCredentials.put("D4", "sensor4");
		deviceCredentials.put("D5", "sensormalicioso");

		System.out.println("\n--- ⚡ INICIANDO 5 PROCESSOS DE COLETA ---");

		ExecutorService deviceExecutor = Executors.newFixedThreadPool(deviceCredentials.size());

		for (Map.Entry<String, String> entry : deviceCredentials.entrySet()) {

			final String id = entry.getKey();
			final String password = entry.getValue();

			deviceExecutor.submit(() -> {
				try {
					Thread.sleep(new Random().nextInt(1000));
				} catch (InterruptedException ignored) {
					Thread.currentThread().interrupt();
				}

				new Device(id, password).start();
			});
		}

		deviceExecutor.shutdown();
		System.out.println("\n--- TODOS OS DISPOSITIVOS FORAM DISPARADOS ---");

		try {
			if (deviceExecutor.awaitTermination(4, TimeUnit.MINUTES)) {
				System.out.println("--- ✅ SIMULAÇÃO DE COLETA CONCLUÍDA ---");
			} else {
				System.out.println("--- ⚠️ Atenção: Dispositivos ainda ativos após 4 minutos. ---");
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
