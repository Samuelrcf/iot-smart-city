package server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
// Removida importação do Gson

import security.SecurityUtils;

public class Device {

	private final String deviceId;
	private final String password;
	private final Random random = new Random();
	private static long dataIdCounter = 1; // Contador sequencial para o ID dos dados

	public Device(String deviceId, String password) {
		this.deviceId = deviceId;
		this.password = password;
	}

	// --- MÉTODO DE Geração de Dados Aleatórios (Mantido) ---
	private ClimateData generateRandomClimateData() {
		// Faixas de dados baseadas no seu plano original
		double co2 = 350 + (600 - 350) * random.nextDouble(); // 350 - 600 ppm
		double co = 0 + (50 - 0) * random.nextDouble(); // 0 - 50 ppm
		double no2 = 0 + (150 - 0) * random.nextDouble(); // 0 - 150 µg/m³
		double so2 = 0 + (50 - 0) * random.nextDouble(); // 0 - 50 µg/m³
		double pm25 = 0 + (200 - 0) * random.nextDouble(); // 0 - 200 µg/m³
		double pm10 = 0 + (200 - 0) * random.nextDouble(); // 0 - 200 µg/m³
		double umidade = 30 + (90 - 30) * random.nextDouble(); // 30 - 90 %
		double temperatura = 15 + (40 - 15) * random.nextDouble(); // 15 - 40 °C
		double ruido = 30 + (90 - 30) * random.nextDouble(); // 30 - 90 dB
		double radiacao = 0 + (10 - 0) * random.nextDouble(); // 0 - 10 (Índice UV)

		return new ClimateData(dataIdCounter++, LocalDateTime.now(), co2, co, no2, so2, pm25, pm10, umidade,
				temperatura, ruido, radiacao);
	}

	public void start() {
		System.out.println("\n--- Dispositivo " + deviceId + " iniciando fluxo... ---");

		// --- 1. Descoberta de Serviço ---
		String authAddress = discoverService();
		if (authAddress == null)
			return;

		// --- 2. Autenticação (Redirecionamento) ---
		String edgeAddress = authenticate(authAddress);
		if (edgeAddress == null)
			return;

		// --- 3. Conexão com Borda e Comunicação Criptografada ---
		connectToEdge(edgeAddress);
	}

	private String discoverService() {
		// [CÓDIGO discoverService() INALTERADO]
		System.out.println("🗺️ Dispositivo: Conectando ao LocationService...");
		try (Socket socket = new Socket(LocationService.LOCATION_ADDRESS, 9000);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));) {
			String response = in.readLine();
			if (response != null && response.startsWith("AUTH_REDIRECT:")) {
				return response.substring(14);
			}
		} catch (Exception e) {
			System.err.println("❌ Dispositivo: Erro na Descoberta: " + e.getMessage());
		}
		return null;
	}

	private String authenticate(String authAddress) {
		// [CÓDIGO authenticate() INALTERADO]
		String[] parts = authAddress.split(":");
		String host = parts[0];
		int port = Integer.parseInt(parts[1]);

		System.out.println("🔑 Dispositivo: Conectando ao AuthService em " + authAddress + "...");

		try (Socket socket = new Socket(host, port);
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));) {
			// Envia credenciais
			out.println("CRED:" + deviceId + ":" + password);

			String response = in.readLine();
			if (response != null && response.startsWith("AUTH_SUCCESS:")) {
				return response.substring(13); // Retorna o endereço da Borda
			} else {
				System.err.println("❌ Dispositivo: Falha na autenticação: " + response);
			}
		} catch (Exception e) {
			System.err.println("❌ Dispositivo: Erro na Autenticação: " + e.getMessage());
		}
		return null;
	}

	private void connectToEdge(String edgeAddress) {
		String[] parts = edgeAddress.split(":");
		String host = parts[0];
		int port = Integer.parseInt(parts[1]);

		System.out.println("💻 Dispositivo: Conectando ao EdgeService em " + edgeAddress + "...");

		SecretKey symmetricKey = null; // Chave declarada fora do try-with-resources TCP
		InetAddress edgeAddressUDP = null; // Endereço para o DatagramSocket

		// --- FASE 1: CONEXÃO TCP (TROCA DE CHAVES E ID) ---
		try (Socket socket = new Socket(host, port);
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));) {

			// --- 1. Troca de Chaves Criptografada (RSA) ---
			symmetricKey = SecurityUtils.generateAESKey();
			PublicKey edgePublicKey = SecurityUtils.getEdgePublicKey();

			System.out.println("🔑 Dispositivo: Chave AES gerada. Criptografando com RSA...");

			byte[] encryptedSymmetricKey = SecurityUtils.encryptSymmetricKey(symmetricKey, edgePublicKey);
			out.println(Base64.getEncoder().encodeToString(encryptedSymmetricKey));

			if (!"KEY_EXCHANGE_SUCCESS".equals(in.readLine())) {
				throw new Exception("Falha na troca de chaves.");
			}

			System.out.println("💻 Dispositivo: Chave Simétrica estabelecida com a Borda.");

			// --- NOVO PASSO: IDENTIFICAÇÃO DO DISPOSITIVO ---
			out.println("DEVICE_ID:" + deviceId);
			System.out.println("🏷️ Dispositivo: Enviou ID (" + deviceId + ") para identificação.");

			// Define o endereço para o UDP antes de fechar o socket TCP
			edgeAddressUDP = InetAddress.getByName(host);

		} catch (Exception e) {
			System.err.println("❌ Dispositivo " + deviceId + ": Erro na FASE TCP (Chaves/ID): " + e.getMessage());
			return; // Se a fase TCP falhar, encerra
		}

		// --- FASE 2: ENVIO DE DADOS VIA UDP ---
		System.out.println(" UDP: Iniciando envio de dados climáticos...");

		try (DatagramSocket udpSocket = new DatagramSocket()) {

			long startTime = System.currentTimeMillis();
			long endTime = startTime + (3 * 60 * 1000); // 3 minutos em milissegundos

			while (System.currentTimeMillis() < endTime) {
				// 2a. Gerar Dados
				ClimateData dataObject = generateRandomClimateData();
				String dataString = dataObject.toString();

				// 2b. Criptografar TUDO (apenas dados climáticos)
				byte[] encryptedData = SecurityUtils.encryptData(dataString, symmetricKey);

				// 2c. Enviar o ID e os Dados Criptografados juntos no pacote UDP
				// NOTA: Para enviar dois campos em um DatagramPacket, precisamos de um
				// delimitador customizado.

				String payload = deviceId + "|" + Base64.getEncoder().encodeToString(encryptedData);
				byte[] dataPacketBytes = payload.getBytes("UTF-8");

				DatagramPacket packet = new DatagramPacket(dataPacketBytes, dataPacketBytes.length, edgeAddressUDP,
						port);
				udpSocket.send(packet);

				System.out.println("[" + deviceId + "] Pacote UDP enviado: " + dataString);

				Thread.sleep(2000 + random.nextInt(1000)); // Intervalo de 2 a 3 segundos
			}

			System.out.println("--- Dispositivo " + deviceId + ": Fim do ciclo de 3 minutos. Encerrando UDP. ---");

		} catch (Exception e) {
			System.err.println("❌ Dispositivo " + deviceId + ": Erro na FASE UDP: " + e.getMessage());
		}
	}

	public static void main(String[] args) {

		// 1. Definição das Credenciais dos 5 Dispositivos
		Map<String, String> deviceCredentials = new LinkedHashMap<>();
		deviceCredentials.put("D1", "sensor1");
		deviceCredentials.put("D2", "sensor2");
		deviceCredentials.put("D3", "sensor3");
		deviceCredentials.put("D4", "sensor4");
		deviceCredentials.put("D5", "sensormalicioso"); // Dispositivo malicioso/inválido

		// --- INÍCIO DA SIMULAÇÃO DE CLIENTES ---

		// --- 2. INICIALIZAÇÃO DOS 5 DISPOSITIVOS SIMULTANEAMENTE ---
		System.out.println("\n--- ⚡ INICIANDO 5 PROCESSOS DE COLETA (4 Válidos + 1 Malicioso) ---");

		ExecutorService deviceExecutor = Executors.newFixedThreadPool(deviceCredentials.size());

		for (Map.Entry<String, String> entry : deviceCredentials.entrySet()) {
			final String id = entry.getKey();
			final String password = entry.getValue();

			// Cada dispositivo é submetido ao ExecutorService (1 Thread por Dispositivo)
			deviceExecutor.submit(() -> {
				// CRÍTICO: Delay aleatório para evitar a concorrência extrema (Padding Error)
				try {
					Thread.sleep(new Random().nextInt(1000)); // Delay de 0 a 1 segundo
				} catch (InterruptedException ignored) {
					Thread.currentThread().interrupt();
				}

				Device device = new Device(id, password);
				device.start();
			});
		}

		// Encerrar o ExecutorService e aguardar a finalização dos ciclos de 3 minutos
		deviceExecutor.shutdown();

		System.out.println("\n--- TODOS OS DISPOSITIVOS FORAM DISPARADOS ---");

		try {
			if (deviceExecutor.awaitTermination(4, TimeUnit.MINUTES)) {
				System.out.println("--- ✅ SIMULAÇÃO DE COLETA CONCLUÍDA ---");
			} else {
				System.out.println("--- ⚠️ ATENÇÃO: Dispositivos ainda ativos após 4 minutos. ---");
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}

		// REMOVIDO: Lógica para fechar os servidores, pois eles devem ser encerrados
		// manualmente ou por meio de um mecanismo de encerramento remoto.
	}
}