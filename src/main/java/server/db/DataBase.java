package server.db;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;

import server.ClimateData;
import server.security.CryptoManager;

public class DataBase {

	public static final int DB_PORT = 9091; // Porta para comunicação DB interna
	private static final String DC_BD_FILE = "datacenter_db.txt";

	private KeyPair dbKeyPair;

	public DataBase() throws NoSuchAlgorithmException {
		// Geração da chave RSA para comunicação interna (DataCenter <-> DB)
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		this.dbKeyPair = keyGen.generateKeyPair();
	}

	public PublicKey getPublicKey() {
		return this.dbKeyPair.getPublic();
	}

	public PrivateKey getPrivateKey() {
		return this.dbKeyPair.getPrivate();
	}

	public void start() {
		try (ServerSocket serverSocket = new ServerSocket(DB_PORT)) {
			System.out.printf("💾 DataCenterDB ativo na porta %d.\n", DB_PORT);
			while (true) {
				Socket clientSocket = serverSocket.accept();
				new Thread(() -> handleDBConnection(clientSocket)).start();
			}
		} catch (Exception e) {
			System.err.println("❌ DataCenterDB falhou: " + e.getMessage());
		}
	}

	private void handleDBConnection(Socket socket) {
		SecretKey symmetricKey = null;

		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			// 1. Deve começar com REQUEST_PUB_KEY
			String line = in.readLine();
			if (line == null)
				return;

			if (!line.equals("REQUEST_PUB_KEY")) {
				System.err.println("Protocolo inválido no DB!");
				return;
			}

			// 2. Envia chave pública
			String pubKeyB64 = Base64.getEncoder().encodeToString(this.getPublicKey().getEncoded());
			out.println("PUB_KEY_B64:" + pubKeyB64);

			// 3. Espera AES_KEY_B64
			line = in.readLine();
			if (line == null || !line.startsWith("AES_KEY_B64:"))
				return;

			byte[] encryptedSymKey = Base64.getDecoder().decode(line.substring(12));
			symmetricKey = CryptoManager.decryptSymmetricKey(encryptedSymKey, this.getPrivateKey());

			out.println("KEY_EXCHANGE_SUCCESS");

			// ---------------------------------------
			// 4. LOOP DE RECEPÇÃO DE MÚLTIPLAS MENSAGENS
			String encryptedDataLine;

			while ((encryptedDataLine = in.readLine()) != null) {

				String decryptedData = CryptoManager.decryptAES(Base64.getDecoder().decode(encryptedDataLine),
						symmetricKey);

				// -------------------------------------------
				// NOVAS OPERAÇÕES (requisições do DataCenter)
				// -------------------------------------------
				if (decryptedData.equals("GET_REPORT")) {
					String report = generateReport();
					String encrypted = Base64.getEncoder()
							.encodeToString(CryptoManager.encryptAES(report, symmetricKey));
					out.println(encrypted);
					continue;
				}

				if (decryptedData.equals("GET_ALERTS")) {
					String alerts = generateAlerts();
					String encrypted = Base64.getEncoder()
							.encodeToString(CryptoManager.encryptAES(alerts, symmetricKey));
					out.println(encrypted);
					continue;
				}

				if (decryptedData.equals("GET_FORECAST")) {
					String forecast = generateForecast();
					String encrypted = Base64.getEncoder()
							.encodeToString(CryptoManager.encryptAES(forecast, symmetricKey));
					out.println(encrypted);
					continue;
				}
				
				if (decryptedData.equals("GET_DATA")) {
					String forecast = getData();
					String encrypted = Base64.getEncoder()
							.encodeToString(CryptoManager.encryptAES(forecast, symmetricKey));
					out.println(encrypted);
					continue;
				}

				// -------------------------------------------
				// MODO ATUAL: RECEBE DADOS DO DATACENTER
				// -------------------------------------------
				saveDataToFile(decryptedData);

				out.println("DB_ACK");
			}

		} catch (Exception e) {
			System.err.println("❌ Erro na conexão interna com DB: " + e.getMessage());
		}
	}

	private void saveDataToFile(String data) throws IOException {
		try (PrintWriter writer = new PrintWriter(new FileWriter(DC_BD_FILE, true))) {
			writer.println(data);
		}
	}

	public static void main(String[] args) {
		try {
			DataBase db = new DataBase();
			db.start();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Falha ao iniciar DataCenterDB: " + e.getMessage());
		}
	}

	private List<ClimateData> loadAllData() throws IOException {
		List<ClimateData> list = new ArrayList<>();

		try (BufferedReader reader = new BufferedReader(new java.io.FileReader(DC_BD_FILE))) {
			String line;
			while ((line = reader.readLine()) != null) {
				ClimateData data = ClimateData.parse(line);
				if (data != null) {
					list.add(data);
				}
			}
		}
		return list;
	}

	private String generateReport() {
		try {
			List<ClimateData> list = loadAllData();
			if (list.isEmpty())
				return "Nenhum dado disponível.";

			double avgTemp = list.stream().mapToDouble(d -> d.getTemperatura()).average().orElse(0);
			double maxTemp = list.stream().mapToDouble(d -> d.getTemperatura()).max().orElse(0);
			double minTemp = list.stream().mapToDouble(d -> d.getTemperatura()).min().orElse(0);

			double avgCO2 = list.stream().mapToDouble(d -> d.getCo2()).average().orElse(0);
			double maxCO2 = list.stream().mapToDouble(d -> d.getCo2()).max().orElse(0);

			double avgNO2 = list.stream().mapToDouble(d -> d.getNo2()).average().orElse(0);
			double maxNO2 = list.stream().mapToDouble(d -> d.getNo2()).max().orElse(0);

			return "📊 RELATÓRIO DO BANCO DE DADOS\n\n" + "Temperatura:\n" + " • Média: "
					+ String.format("%.2f", avgTemp) + "°C\n" + " • Mínima: " + String.format("%.2f", minTemp) + "°C\n"
					+ " • Máxima: " + String.format("%.2f", maxTemp) + "°C\n\n" +

					"CO₂:\n" + " • Média: " + String.format("%.2f", avgCO2) + " ppm\n" + " • Máximo: "
					+ String.format("%.2f", maxCO2) + " ppm\n\n" +

					"NO₂:\n" + " • Média: " + String.format("%.2f", avgNO2) + " ppm\n" + " • Máximo: "
					+ String.format("%.2f", maxNO2) + " ppm\n\n" +

					"Total de registros analisados: " + list.size();

		} catch (Exception e) {
			return "Erro ao gerar relatório: " + e.getMessage();
		}
	}

	private String generateAlerts() {
		try {
			List<ClimateData> list = loadAllData();
			if (list.isEmpty())
				return "Sem dados para analisar.";

			StringBuilder sb = new StringBuilder("🚨 ALERTAS DETECTADOS:\n\n");

			for (ClimateData d : list) {

				if (d.getCo2() > 600)
					sb.append("• CO₂ muito alto no registro ").append(d.getId()).append("\n");

				if (d.getNo2() > 120)
					sb.append("• NO₂ acima do limite seguro no registro ").append(d.getId()).append("\n");

				if (d.getPm25() > 100)
					sb.append("• PM2.5 em nível perigoso no registro ").append(d.getId()).append("\n");

				if (d.getTemperatura() > 40)
					sb.append("• Temperatura extrema no registro ").append(d.getId()).append("\n");
			}

			if (sb.toString().equals("🚨 ALERTAS DETECTADOS:\n\n"))
				return "Nenhum alerta detectado.";

			return sb.toString();

		} catch (Exception e) {
			return "Erro ao gerar alertas: " + e.getMessage();
		}
	}

	private String generateForecast() {
		try {
			List<ClimateData> list = loadAllData();
			if (list.size() < 5)
				return "Dados insuficientes para previsão.";

			int size = list.size();
			List<ClimateData> last = list.subList(size - 5, size);

			double trendTemp = last.get(last.size() - 1).getTemperatura() - last.get(0).getTemperatura();
			String tendencia = trendTemp > 0 ? "aumentando" : "diminuindo";

			double prediction = last.get(last.size() - 1).getTemperatura() + (trendTemp * 0.25);

			return "📈 PREVISÃO SIMPLES\n\n" + "Tendência de temperatura dos últimos 5 registros:\n" + " - Variação: "
					+ String.format("%.2f", trendTemp) + "°C\n" + " - Tendência: temperatura está " + tendencia + "\n\n"
					+ "Previsão para a próxima hora:\n" + " - Estimativa: " + String.format("%.2f", prediction) + "°C";

		} catch (Exception e) {
			return "Erro ao gerar previsão: " + e.getMessage();
		}
	}
	
	public String getData() {
	    List<String> lines = new ArrayList<>();

	    try (BufferedReader reader = new BufferedReader(new java.io.FileReader(DC_BD_FILE))) {
	        String line;
	        while ((line = reader.readLine()) != null) {
	            lines.add(line);
	        }
	    } catch (Exception e) {
	        return "Erro ao ler banco de dados: " + e.getMessage();
	    }

	    if (lines.isEmpty()) {
	        return "Nenhum dado armazenado.";
	    }

	    StringBuilder sb = new StringBuilder();
	    sb.append("📌 ÚLTIMOS REGISTROS ARMAZENADOS\n\n");

	    int start = Math.max(0, lines.size() - 10);

	    for (int i = start; i < lines.size(); i++) {
	        ClimateData data = ClimateData.parse(lines.get(i));
	        if (data != null) {
	            sb.append(data.toString()).append("\n");
	        }
	    }

	    return sb.toString();
	}


}
