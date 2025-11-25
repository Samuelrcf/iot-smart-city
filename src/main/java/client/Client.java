package client;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Client {

	private SecretKey sessionAESKey;
	private String datacenterAddress;
	private final String username = "samuel";
	private final String password = "12345";
	private String jwtToken;

	public void start() throws Exception {

		discoverDataCenter();

		PublicKey dcPublicKey = fetchPublicKey();

		sessionAESKey = generateAESKey();

		sendAESKey(dcPublicKey);

		String dados = requestProtected("/dados");
		String relatorios = requestProtected("/relatorios");
		String alertas = requestProtected("/alertas");
		String previsoes = requestProtected("/previsoes");

		System.out.println("\n[INFO] Dados = " + dados);
		System.out.println("[INFO] Relatórios = " + relatorios);
		System.out.println("[ALERTA] Alertas = " + alertas);
		System.out.println("[INFO] Previsões = " + previsoes);
	}

	// -------------------------------------------------------------------------
	// 1. Descoberta
	// -------------------------------------------------------------------------
	private void discoverDataCenter() throws Exception {
		URI uri = new URI("http://127.0.0.1:9001/client"); // endereço do localizador
		URL url = uri.toURL();
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");

		String response = new String(conn.getInputStream().readAllBytes());

		datacenterAddress = response.substring("HTTP_REDIRECT:".length());
		System.out.println("[INFO] Cliente descobriu DataCenter em: " + datacenterAddress);
	}

	// -------------------------------------------------------------------------
	// 2. Baixa chave pública
	// -------------------------------------------------------------------------
	private PublicKey fetchPublicKey() throws Exception {
		URI uri = new URI(datacenterAddress + "/publickey");
		URL url = uri.toURL();
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");

		byte[] keyBytes = conn.getInputStream().readAllBytes();
		byte[] decoded = Base64.getDecoder().decode(keyBytes);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded); // encapsula os bytes binários da chave pública
		return KeyFactory.getInstance("RSA").generatePublic(spec);
	}

	// -------------------------------------------------------------------------
	// 3. AES key
	// -------------------------------------------------------------------------
	private SecretKey generateAESKey() throws Exception {
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		return gen.generateKey();
	}

	// -------------------------------------------------------------------------
	// 4. Handshake
	// -------------------------------------------------------------------------
	private void sendAESKey(PublicKey publicKey) throws Exception {
		// 1) monta payload
		String aesB64 = Base64.getEncoder().encodeToString(sessionAESKey.getEncoded());
		String payload = "USER=" + username + "\n" + "PASS=" + password + "\n" + "AES=" + aesB64 + "\n";

		// 2) cifra com RSA/OAEP
		Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		rsa.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encrypted = rsa.doFinal(payload.getBytes("UTF-8"));
		String encryptedB64 = Base64.getEncoder().encodeToString(encrypted);

		// 3) POST para /auth
		URI uri = new URI(datacenterAddress + "/auth");
		URL url = uri.toURL();
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setConnectTimeout(5000);
		conn.setReadTimeout(5000);
		conn.setRequestProperty("Content-Type", "application/octet-stream; charset=UTF-8");

		try (OutputStream os = conn.getOutputStream()) {
			byte[] outBytes = encryptedB64.getBytes("UTF-8");
			os.write(outBytes);
			os.flush();
		}

		// 4) verifica response code
		int responseCode = conn.getResponseCode();
		if (responseCode != 200) {
			throw new RuntimeException("Falha na autenticação: HTTP " + responseCode);
		}

		// 5) lê JWT do header Authorization
		String authHeader = conn.getHeaderField("Authorization");
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			jwtToken = authHeader.substring(7);
			System.out.println("[OK] Chave AES enviada e JWT recebido.");
		} else {
			throw new RuntimeException("JWT não recebido do DataCenter (header Authorization ausente).");
		}

		// 6) consome input stream (para liberar conexão) e desconecta
		try (InputStream is = conn.getInputStream()) {
			if (is != null)
				is.readAllBytes();
		} finally {
			conn.disconnect();
		}
	}

	private String requestProtected(String path) throws Exception {
		URI uri = new URI(datacenterAddress + path);
		URL url = uri.toURL();

		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");
		conn.setConnectTimeout(5000);
		conn.setReadTimeout(5000);

		if (jwtToken == null || jwtToken.isBlank()) {
			throw new IllegalStateException("JWT ausente. Autentique primeiro.");
		}

		conn.setRequestProperty("Authorization", "Bearer " + jwtToken);
		conn.setRequestProperty("Accept", "application/octet-stream");

		int rc = conn.getResponseCode();
		if (rc != 200) {
			throw new RuntimeException("Request protegido falhou: HTTP " + rc);
		}

		byte[] encryptedB64;
		try (InputStream is = conn.getInputStream()) {
			encryptedB64 = is.readAllBytes();
		} finally {
			conn.disconnect();
		}

		if (encryptedB64 == null || encryptedB64.length == 0)
			return "";

		byte[] encrypted = Base64.getDecoder().decode(encryptedB64);

		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aes.init(Cipher.DECRYPT_MODE, sessionAESKey);
		byte[] plain = aes.doFinal(encrypted);

		return new String(plain, "UTF-8");
	}
}
