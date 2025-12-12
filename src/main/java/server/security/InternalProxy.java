package server.security;

import java.io.BufferedReader;
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
import java.util.Base64;

import javax.crypto.SecretKey;

public class InternalProxy {
	private static final int PROXY_PORT = 8090;
	private IDS ids = new IDS();

	private PublicKey proxyPublicKey;
	private PrivateKey proxyPrivateKey;

	public InternalProxy() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair pair = keyGen.generateKeyPair();

			this.proxyPublicKey = pair.getPublic();
			this.proxyPrivateKey = pair.getPrivate();

			System.out.println("[OK] Proxy: Identidade RSA gerada com sucesso.");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Erro ao inicializar chaves do Proxy", e);
		}
	}

	public void start() {
		System.out.println("Firewall Interno ativo na porta " + PROXY_PORT);
		try (ServerSocket serverSocket = new ServerSocket(PROXY_PORT)) {
			while (true) {
				Socket dcSocket = serverSocket.accept();
				new Thread(() -> handleInspection(dcSocket)).start();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void handleInspection(Socket dcSocket) {
		try (BufferedReader inFromDC = new BufferedReader(new InputStreamReader(dcSocket.getInputStream()));
				PrintWriter outToDC = new PrintWriter(dcSocket.getOutputStream(), true);
				Socket dbSocket = new Socket("127.0.0.1", 9091);
				PrintWriter outToDB = new PrintWriter(dbSocket.getOutputStream(), true);
				BufferedReader inFromDB = new BufferedReader(new InputStreamReader(dbSocket.getInputStream()))) {

			String requestFromDC = inFromDC.readLine();
			if ("REQUEST_PUB_KEY".equals(requestFromDC)) {
				outToDC.println("PUB_KEY_B64:" + Base64.getEncoder().encodeToString(this.proxyPublicKey.getEncoded()));

				String aesFromDC = inFromDC.readLine();
				byte[] encKeyFromDC = Base64.getDecoder().decode(aesFromDC.substring(12));
				SecretKey symKeyWithDC = CryptoManager.decryptSymmetricKey(encKeyFromDC, this.proxyPrivateKey);
				outToDC.println("KEY_EXCHANGE_SUCCESS");

				outToDB.println("REQUEST_PUB_KEY");
				String pubKeyFromDB = inFromDB.readLine();
				PublicKey dbPubKey = CryptoManager.reconstructPublicKey(pubKeyFromDB.substring(12));
				SecretKey symKeyWithDB = CryptoManager.generateAESKey();
				byte[] encKeyToDB = CryptoManager.encryptSymmetricKey(symKeyWithDB, dbPubKey);
				outToDB.println("AES_KEY_B64:" + Base64.getEncoder().encodeToString(encKeyToDB));
				inFromDB.readLine(); 

				String encryptedLine;
				while ((encryptedLine = inFromDC.readLine()) != null) {
					String data = CryptoManager.decryptAES(Base64.getDecoder().decode(encryptedLine), symKeyWithDC);
					System.out.println("🧐 [Proxy] Inspecionando dado descriptografado: " + data);

					String anomalyReason = checkDataForAnomalies(data);

					if (anomalyReason != null) {
						System.err
								.println("[Proxy] BLOQUEADO: Tentativa de inserção anômala (" + anomalyReason + ")");
						ids.analyzeTraffic("d5", "DB_Internal", data + " | Motivo: " + anomalyReason);
						outToDC.println("FIREWALL_REJECTED");
					} else {
						String reEncrypted = Base64.getEncoder()
								.encodeToString(CryptoManager.encryptAES(data, symKeyWithDB));
						outToDB.println(reEncrypted);
						outToDC.println(inFromDB.readLine());
					}
				}
			}
		} catch (Exception e) {
			System.err.println("Erro no SSL Offloading do Proxy: " + e.getMessage());
		}
	}

	private String checkDataForAnomalies(String data) {
		double tempValue = extractNumericValue(data, "temperatura=");
		double co2Value = extractNumericValue(data, "co2=");
		double umidadeValue = extractNumericValue(data, "umidade=");

		String dataLower = data.toLowerCase();
		if (dataLower.contains("drop table") || dataLower.contains("delete from") || dataLower.contains("shutdown")) {
			return "INJECAO DE COMANDO";
		}

		if (tempValue >= 150.0) {
			return "TEMPERATURA EXTREMA";
		}

		if (co2Value > 1000.0) {
			return "CO2 EXTREMO";
		}

		if (umidadeValue > 95.0 && tempValue < 0.0) {
			return "INCONSISTENCIA UMIDADE/TEMP";
		}

		return null; 
	}

	private double extractNumericValue(String data, String fieldName) {
		try {
			String target = fieldName;
			int start = data.indexOf(target);
			if (start == -1)
				return 0.0; 

			start += target.length();
			int end = data.indexOf(",", start);
			if (end == -1)
				end = data.indexOf("]", start); 

			String tempStr = data.substring(start, end).trim();
			tempStr = tempStr.replace(",", "."); 

			return Double.parseDouble(tempStr);
		} catch (Exception e) {
			return 0.0;
		}
	}

	public static void main(String[] args) {
		System.out.println("--- INICIANDO SERVIÇO DE FIREWALL INTERNO ---");
		InternalProxy proxy = new InternalProxy();
		proxy.start();
	}
}
