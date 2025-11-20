package server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class LocationService {

	private static final int LOCATION_PORT = 9000;
	public static final int AUTH_PORT = 8080;
	public static final String LOCATION_ADDRESS = "127.0.0.1";

	// Método que inicia o Servidor de Localização
	public void start() {
		System.out.printf("🗺️ LocationService iniciado na porta %d...%n", LOCATION_PORT);

		try (ServerSocket serverSocket = new ServerSocket(LOCATION_PORT)) {
			while (true) {
				Socket clientSocket = serverSocket.accept();
				new Thread(() -> handleDeviceConnection(clientSocket)).start();
			}
		} catch (Exception e) {
			System.err.println("❌ LocationService parou inesperadamente: " + e.getMessage());
		}
	}

	private void handleDeviceConnection(Socket socket) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);) {
			System.out.println("\n📡 LocationService: Novo dispositivo conectado para descoberta.");

			// 1. REDIRECIONAMENTO PARA AUTENTICAÇÃO
			String authAddress = EdgeService.BORDER_ADDRESS + ":" + AUTH_PORT;
			out.println("AUTH_REDIRECT:" + authAddress);
			System.out.println("🗺️ LocationService: Redirecionado para Autenticação em " + authAddress);

			// O LocationService encerra sua parte aqui, o Dispositivo se conecta ao
			// servidor de AUTENTICAÇÃO

		} catch (Exception e) {
			System.err.println("❌ Erro no LocationService: " + e.getMessage());
		}
	}

	// --- MÉTODOS DE AUTENTICAÇÃO SIMULADOS (No LocationService, ele apenas
	// gerencia o fluxo) ---
	// Em um cenário real, Autenticação seria um Serviço separado. Aqui,
	// simplificamos a lógica de autenticação
	// no SecurityUtils e o servidor LocationService apenas gerencia o fluxo de
	// portas.

	// Este método simula o Servidor de Autenticação (pode ser iniciado como um
	// processo separado se necessário)
	public void startAuthServer() {
		System.out.printf("🔑 AuthService iniciado na porta %d...%n", AUTH_PORT);
		try (ServerSocket authSocket = new ServerSocket(AUTH_PORT)) {
			while (true) {
				Socket deviceSocket = authSocket.accept();
				new Thread(() -> handleAuthRequest(deviceSocket)).start();
			}
		} catch (Exception e) {
			System.err.println("❌ AuthService parou inesperadamente: " + e.getMessage());
		}
	}

	private void handleAuthRequest(Socket socket) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);) {
			// Espera pelas credenciais (simuladas)
			String credentialsLine = in.readLine();
			if (credentialsLine == null || !credentialsLine.startsWith("CRED:")) {
				out.println("AUTH_FAIL: Invalid request format.");
				return;
			}

			String[] parts = credentialsLine.substring(5).split(":");
			if (parts.length != 2) {
				out.println("AUTH_FAIL: Malformed credentials.");
				return;
			}

			String deviceId = parts[0];
			String password = parts[1];

			if (EdgeService.authenticateDevice(deviceId, password)) {
				// Autenticado com sucesso, redireciona para a Borda
				String edgeAddress = EdgeService.BORDER_ADDRESS + ":" + EdgeService.EDGE_PORT;
				out.println("AUTH_SUCCESS:" + edgeAddress);
				System.out.println("🔑 AuthService: Dispositivo " + deviceId
						+ " autenticado e redirecionado para a Borda em " + edgeAddress);
			} else {
				out.println("AUTH_FAIL: Invalid credentials.");
				System.out.println("🔑 AuthService: Falha de autenticação para " + deviceId);
			}

		} catch (Exception e) {
			System.err.println("❌ Erro no AuthService: " + e.getMessage());
		}
	}

	public static void main(String[] args) {
		System.out.println("--- 🚀 INICIANDO PROCESSO DE LOCALIZAÇÃO E AUTENTICAÇÃO ---");
		LocationService service = new LocationService();

		// Iniciamos os servidores de Location (porta 9000) e Auth (porta 8080)
		// em threads, mas dentro deste único processo Java.
		new Thread(() -> service.start(), "Location-Server").start();
		new Thread(() -> service.startAuthServer(), "Auth-Server").start();
	}

}