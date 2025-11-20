package security;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGenerator {

    public static final String PUBLIC_KEY_FILE = "edge_public.key";
    public static final String PRIVATE_KEY_FILE = "edge_private.key";

    public static void main(String[] args) throws Exception {
        System.out.println("--- 🔑 GERADOR DE CHAVES RSA INICIADO ---");
        
        // 1. Gerar o Par de Chaves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        
        // 2. Salvar Chave Pública (Para o Dispositivo)
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE))) {
            oos.writeObject(pair.getPublic());
            System.out.println("✅ Chave Pública salva em: " + PUBLIC_KEY_FILE);
        }
        
        // 3. Salvar Chave Privada (Para o Servidor Edge)
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {
            oos.writeObject(pair.getPrivate());
            System.out.println("✅ Chave Privada salva em: " + PRIVATE_KEY_FILE);
        }
        
        System.out.println("--- Geração concluída. Execute este processo APENAS uma vez! ---");
    }
}