package client;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Client {

    private final String clientId = "CLIENTE_001";

    private SecretKey sessionAESKey; 
    private String datacenterAddress;   // Obtido via localizador


    // -------------------------------------------------------------------------
    // INÍCIO DO FLUXO DO CLIENTE
    // -------------------------------------------------------------------------
    public void start() throws Exception {

        discoverDataCenter();                 // 1. Descoberta
        PublicKey dcPublicKey = fetchPublicKey();   // 2. Baixa chave RSA

        sessionAESKey = generateAESKey();     // 3. Gera chave AES

        sendAESKey(dcPublicKey);              // 4. Handshake

        // 5. Requisições protegidas
        String dados     = requestProtected("/dados");
        String relatorios = requestProtected("/relatorios");
        String alertas    = requestProtected("/alertas");
        String previsoes  = requestProtected("/previsoes");

        System.out.println("\n📌 Dados      = " + dados);
        System.out.println("📌 Relatórios = " + relatorios);
        System.out.println("📌 Alertas    = " + alertas);
        System.out.println("📌 Previsões  = " + previsoes);
    }


    // -------------------------------------------------------------------------
    // 1. Descoberta via Localizador HTTP
    // -------------------------------------------------------------------------
    private void discoverDataCenter() throws Exception {
        URL url = new URL("http://127.0.0.1:9001/client");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        String response = new String(conn.getInputStream().readAllBytes());

        if (!response.startsWith("HTTP_REDIRECT:")) {
            throw new RuntimeException("Resposta inesperada do Localizador: " + response);
        }

        datacenterAddress = response.substring("HTTP_REDIRECT:".length());

        System.out.println("🛰️ Cliente descobriu DataCenter em: " + datacenterAddress);
    }


    // -------------------------------------------------------------------------
    // 2. Baixa chave pública do DataCenter
    // -------------------------------------------------------------------------
    private PublicKey fetchPublicKey() throws Exception {
        URL url = new URL(datacenterAddress + "/publickey");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        byte[] keyBytes = conn.getInputStream().readAllBytes();
        byte[] decoded = Base64.getDecoder().decode(keyBytes);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }


    // -------------------------------------------------------------------------
    // 3. Gera chave AES da sessão
    // -------------------------------------------------------------------------
    private SecretKey generateAESKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128); // AES-128 (pode trocar p/ 256 se quiser)
        return gen.generateKey();
    }


    // -------------------------------------------------------------------------
    // 4. Handshake: envia a chave AES cifrada com RSA
    // -------------------------------------------------------------------------
    private void sendAESKey(PublicKey publicKey) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedAES = rsa.doFinal(sessionAESKey.getEncoded());
        String encryptedB64 = Base64.getEncoder().encodeToString(encryptedAES);

        URL url = new URL(datacenterAddress + "/auth");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Client-ID", clientId);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(encryptedB64.getBytes());
        }

        conn.getInputStream().close();

        System.out.println("🔐 Chave AES enviada ao DataCenter.");
    }


    // -------------------------------------------------------------------------
    // 5. Requisições protegidas por AES
    // -------------------------------------------------------------------------
    private String requestProtected(String path) throws Exception {

        URL url = new URL(datacenterAddress + path);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Client-ID", clientId);

        // Recebe dados criptografados (Base64 de AES)
        byte[] encrypted = conn.getInputStream().readAllBytes();
        byte[] decoded = Base64.getDecoder().decode(encrypted);

        Cipher aes = Cipher.getInstance("AES");
        aes.init(Cipher.DECRYPT_MODE, sessionAESKey);

        return new String(aes.doFinal(decoded));
    }
}
