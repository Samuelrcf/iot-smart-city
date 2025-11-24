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
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Device {

	private final String deviceId;
	private final String password;
	private final Random random = new Random();
	private static long dataIdCounter = 1;

	public Device(String deviceId, String password) {
		this.deviceId = deviceId;
		this.password = password;
	}

	public void start() {
		System.out.println("\n[INFO] Dispositivo " + deviceId + " iniciando fluxo...");

		String authAddress = discoverService();
		if (authAddress == null)
			return;

		String edgeAddress = authenticate(authAddress);
		if (edgeAddress == null)
			return;

		connectToEdge(edgeAddress);
	}

	// ================================================================
	// 4. DESCOBERTA E AUTENTICAÇÃO
	// ================================================================
	private String discoverService() {
		System.out.println("[INFO] Dispositivo: Conectando ao LocationService...");

		try (Socket socket = new Socket(LocationService.LOCATION_ADDRESS, 9000);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

			String response = in.readLine();
			if (response != null && response.startsWith("AUTH_REDIRECT:")) {
				return response.substring(14);
			}

		} catch (Exception e) {
			System.err.println("[ERRO] Dispositivo: Erro na Descoberta: " + e.getMessage());
		}
		return null;
	}

	private String authenticate(String authAddress) {
		String[] parts = authAddress.split(":");
		String host = parts[0];
		int port = Integer.parseInt(parts[1]);

		System.out.println("[INFO] Dispositivo: Conectando ao AuthService em " + authAddress + "...");

		try (Socket socket = new Socket(host, port);
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

			out.println("CRED:" + deviceId + ":" + password);

			String response = in.readLine();
			if (response != null && response.startsWith("AUTH_SUCCESS:")) {
				return response.substring(13);
			}

			System.err.println("[ERRO] Dispositivo: Falha na autenticação: " + response);

		} catch (Exception e) {
			System.err.println("[ERRO] Dispositivo: Erro na Autenticação: " + e.getMessage());
		}
		return null;
	}

	// ================================================================
	// 4.3 HANDSHAKE TCP + ENVIO UDP
	// ================================================================
	private void connectToEdge(String edgeAddress) {
		String[] parts = edgeAddress.split(":");
		String host = parts[0];
		int port = Integer.parseInt(parts[1]);

		System.out.println("[INFO] Dispositivo: Conectando ao EdgeService em " + edgeAddress + "...");

		SecretKey symmetricKey = null;
		InetAddress edgeAddressUDP;

		// ----------------------------- FASE 1 — HANDSHAKE TCP (RSA + AES + HMAC)
		try (Socket socket = new Socket(host, port);
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

			// 1) Solicita chave pública
			out.println("REQUEST_PUB_KEY");

			String line = in.readLine();
			if (line == null || !line.startsWith("EDGE_PUB_KEY:")) {
				throw new Exception("Chave pública não recebida do Edge.");
			}

			String pubKeyB64 = line.substring(13);
			byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyB64);

			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey edgePublicKey = kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

			System.out.println("[INFO] Dispositivo: Chave pública recebida do Edge.");

			// 2) Gera chave AES
			symmetricKey = generateAESKey();

			// 3) Envia chave AES criptografada com RSA
			byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, edgePublicKey);
			out.println(Base64.getEncoder().encodeToString(encryptedSymmetricKey));

			// 4) Edge confirma AES recebida
			if (!"KEY_EXCHANGE_SUCCESS".equals(in.readLine())) {
				throw new Exception("Falha no handshake de chave.");
			}

			System.out.println("[OK] Dispositivo: Troca de chaves concluída.");

			// 5) Envia o deviceId para identificação
			out.println("DEVICE_ID:" + deviceId);

			// 6) Calcula e envia HMAC para autenticação
			String hmac = hmacSHA256(deviceId, password);
			out.println("HMAC:" + hmac);

			System.out.println("[INFO] Dispositivo: HMAC enviado para autenticação.");

			// Edge responde se autenticação foi aceita
			String authResp = in.readLine();
			if (!"AUTH_SUCCESS".equals(authResp)) {
				throw new Exception("Edge rejeitou autenticação HMAC.");
			}

			System.out.println("[OK] Dispositivo autenticado com sucesso via HMAC.");

			// host para UDP
			edgeAddressUDP = InetAddress.getByName(host);

		} catch (Exception e) {
			System.err.println("[ERRO] Dispositivo " + deviceId + ": Falha na fase TCP: " + e.getMessage());
			return;
		}

		// ----------------------------- FASE 2 — ENVIO UDP
		System.out.println("[INFO] UDP: Iniciando envio de dados climáticos.");

		try (DatagramSocket udpSocket = new DatagramSocket()) {

			long startTime = System.currentTimeMillis();
			long endTime = startTime + (1 * 60 * 1000);

			while (System.currentTimeMillis() < endTime) {

				ClimateData dataObject = generateRandomClimateData();
				String dataString = dataObject.toString();

				byte[] encryptedData = encryptData(dataString, symmetricKey);

				String payload = deviceId + "|" + Base64.getEncoder().encodeToString(encryptedData);
				byte[] dataPacketBytes = payload.getBytes("UTF-8");

				DatagramPacket packet = new DatagramPacket(dataPacketBytes, dataPacketBytes.length, edgeAddressUDP,
						port);

				udpSocket.send(packet);

				System.out.println("[INFO] " + deviceId + " enviou pacote UDP: " + dataString);

				Thread.sleep(2000 + random.nextInt(1000));
			}

			System.out.println("[OK] Dispositivo " + deviceId + ": Fim do ciclo UDP de 3 minutos.");

		} catch (Exception e) {
			System.err.println("[ERRO] Dispositivo " + deviceId + ": Falha na FASE UDP: " + e.getMessage());
		}
	}

	// ================================================================
	// 5. GERAÇÃO DE DADOS
	// ================================================================
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

	// ================================================================
	// 6. CRIPTOGRAFIA
	// ================================================================
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
	
	public static String hmacSHA256(String data, String secret) throws Exception {
	    Mac mac = Mac.getInstance("HmacSHA256");
	    SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
	    mac.init(keySpec);
	    byte[] hmacBytes = mac.doFinal(data.getBytes());
	    return Base64.getEncoder().encodeToString(hmacBytes);
	}

	// ================================================================
	// 7. EXECUÇÃO DOS 5 DISPOSITIVOS
	// ================================================================
	public static void main(String[] args) {

		Map<String, String> deviceCredentials = new LinkedHashMap<>();
		deviceCredentials.put("D1", "sensor1");
		deviceCredentials.put("D2", "sensor2");
		deviceCredentials.put("D3", "sensor3");
		deviceCredentials.put("D4", "sensor4");
		deviceCredentials.put("D5", "sensormalicioso");

		System.out.println("\n[INFO] Iniciando 5 processos de coleta...");

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
		System.out.println("[INFO] Todos os dispositivos foram disparados.");

		try {
			if (deviceExecutor.awaitTermination(4, TimeUnit.MINUTES)) {
				System.out.println("[OK] Simulação de coleta concluída.");
			} else {
				System.out.println("[AVISO] Dispositivos ainda ativos após 4 minutos.");
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
