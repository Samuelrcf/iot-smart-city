package server.security;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.time.LocalDateTime;

public class IDS {
	private static final String REPORT_FILE = "ids_security_report.log";

	public void analyzeTraffic(String origin, String target, String content) {
		try (PrintWriter writer = new PrintWriter(new FileWriter(REPORT_FILE, true))) {
			writer.println("--- IDS SECURITY INCIDENT ---");
			writer.println("Data/Hora: " + LocalDateTime.now());
			writer.println("Origem: " + origin);
			writer.println("Destino: " + target);
			writer.println("Conteúdo Suspeito: " + content);
			writer.println("Ação Tomada: Notificar Edge para encerramento.");
			writer.println("-----------------------------\n");
		} catch (Exception e) {
			e.printStackTrace();
		}

		triggerEdgeShutdown(origin);
	}

	private void triggerEdgeShutdown(String deviceId) {
	    System.out.println("IDS: avisando Edge para bloquear " + deviceId);

	    try (Socket socket = new Socket("127.0.0.1", 9099);
	         PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

	        out.println("BLOCK:" + deviceId);

	    } catch (Exception e) {
	        System.err.println("Erro ao enviar comando BLOCK ao Edge: " + e.getMessage());
	    }
	}

}