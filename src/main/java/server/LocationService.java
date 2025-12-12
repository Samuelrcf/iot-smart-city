package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

public class LocationService {

	// ----------------------------
	// CONFIGURAÇÕES
	// ----------------------------
	private static final int SOCKET_PORT = 9000;
	private static final int HTTP_PORT = 9001;

	public static final String LOCATION_ADDRESS = "127.0.0.1";
	public static final String DATACENTER_HTTP = "http://127.0.0.1:7000";

	// ----------------------------
	// INICIALIZAÇÃO
	// ----------------------------
	public void start() {
		System.out.println("[INFO] LocationService iniciado");

		startSocketServerAsync();
		startHttpServerAsync();
	}

	private void startSocketServerAsync() {
		new Thread(() -> {
			System.out.println("[INFO] Iniciando SocketListener na porta " + SOCKET_PORT);
			startSocketServer();
		}).start();
	}

	private void startHttpServerAsync() {
		new Thread(() -> {
			System.out.println("[INFO] Iniciando HttpListener na porta " + HTTP_PORT);
			startHttpServer();
		}).start();
	}

	// ----------------------------
	// SERVIDOR SOCKET (IoT)
	// ----------------------------
	private void startSocketServer() {
		try (ServerSocket serverSocket = new ServerSocket(SOCKET_PORT)) {
			System.out.println("[INFO] Aguardando dispositivos (SOCKET)...");

			while (true) {
				Socket client = serverSocket.accept();
				new Thread(() -> handleDevice(client)).start();
			}

		} catch (Exception e) {
			logError("Erro no SocketServer", e);
		}
	}

	private void handleDevice(Socket socket) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			System.out.println("\n[INFO] Novo dispositivo conectado.");

			String authURL = EdgeService.BORDER_ADDRESS + ":" + EdgeService.EDGE_PORT;

			out.println("AUTH_REDIRECT:" + authURL);

			System.out.println("[INFO] Dispositivo redirecionado ao Edge: " + authURL);

		} catch (Exception e) {
			logError("Erro ao tratar dispositivo", e);
		}
	}

	// ----------------------------
	// SERVIDOR HTTP (Clientes)
	// ----------------------------
	private void startHttpServer() {
		try {
			HttpServer http = HttpServer.create(new InetSocketAddress(HTTP_PORT), 0);

			http.createContext("/client", this::handleClientRequest);
			http.start();

			System.out.println("[INFO] HTTP pronto para clientes na porta " + HTTP_PORT);

		} catch (IOException e) {
			logError("Erro no HttpServer", e);
		}
	}

	private void handleClientRequest(HttpExchange exchange) throws IOException {
		if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}

		System.out.println("[INFO] Cliente conectado ao Localizador via HTTP.");

		String redirectMsg = "HTTP_REDIRECT:" + DATACENTER_HTTP;
		byte[] response = redirectMsg.getBytes();

		exchange.sendResponseHeaders(200, response.length);

		try (OutputStream os = exchange.getResponseBody()) {
			os.write(response);
		}

		System.out.println("[INFO] Cliente redirecionado para DataCenter: " + DATACENTER_HTTP);
	}

	// ----------------------------
	// LOG DE ERROS
	// ----------------------------
	private void logError(String msg, Exception e) {
		System.err.println("[ERRO] " + msg + ": " + e.getMessage());
	}

	// ----------------------------
	// MAIN
	// ----------------------------
	public static void main(String[] args) {
		System.out.println("[INFO] --- INICIANDO PROCESSO DE LOCALIZAÇÃO ---");
		new LocationService().start();
	}
}
