package server;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter; // Importação necessária

public class ClimateData {
	private Long id;
	private LocalDateTime timestamp;
	private double co2, co, no2, so2, pm25, pm10, umidade, temperatura, ruido, radiacao;

	private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

	public ClimateData(Long id, LocalDateTime timestamp, double co2, double co, double no2, double so2, double pm25,
			double pm10, double umidade, double temperatura, double ruido, double radiacao) {
		this.id = id;
		this.timestamp = timestamp;
		this.co2 = co2;
		this.co = co;
		this.no2 = no2;
		this.so2 = so2;
		this.pm25 = pm25;
		this.pm10 = pm10;
		this.umidade = umidade;
		this.temperatura = temperatura;
		this.ruido = ruido;
		this.radiacao = radiacao;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(LocalDateTime timestamp) {
		this.timestamp = timestamp;
	}

	public double getCo2() {
		return co2;
	}

	public void setCo2(double co2) {
		this.co2 = co2;
	}

	public double getCo() {
		return co;
	}

	public void setCo(double co) {
		this.co = co;
	}

	public double getNo2() {
		return no2;
	}

	public void setNo2(double no2) {
		this.no2 = no2;
	}

	public double getSo2() {
		return so2;
	}

	public double getPm25() {
		return pm25;
	}

	public double getPm10() {
		return pm10;
	}

	public double getUmidade() {
		return umidade;
	}

	public double getTemperatura() {
		return temperatura;
	}

	public double getRuido() {
		return ruido;
	}

	public double getRadiacao() {
		return radiacao;
	}

	@Override
	public String toString() {
		String formattedTimestamp = timestamp != null ? timestamp.format(FORMATTER) : "null";

		return "Dados Climáticos [id=" + id + ", timestamp=" + formattedTimestamp + ", co2="
				+ String.format("%.2f", co2) + ", co=" + String.format("%.2f", co) + ", no2="
				+ String.format("%.2f", no2) + ", so2=" + String.format("%.2f", so2) + ", pm25="
				+ String.format("%.2f", pm25) + ", pm10=" + String.format("%.2f", pm10) + ", umidade="
				+ String.format("%.2f", umidade) + ", temperatura=" + String.format("%.2f", temperatura) + ", ruido="
				+ String.format("%.2f", ruido) + ", radiacao=" + String.format("%.2f", radiacao) + "]";
	}

	public static ClimateData parse(String line) {
		try {
			line = line.replace("Dados Climáticos [", "").replace("]", "").trim();

			String[] parts = line.split(", ");

			Long id = null;
			LocalDateTime timestamp = null;
			double co2 = 0, co = 0, no2 = 0, so2 = 0, pm25 = 0, pm10 = 0, umidade = 0, temperatura = 0, ruido = 0,
					radiacao = 0;

			for (String p : parts) {
				if (!p.contains("="))
					continue;

				String[] kv = p.split("=", 2);
				String key = kv[0].trim();
				String value = kv[1].trim();

				// Converte decimal BR → US
				value = value.replace(",", ".");

				switch (key) {
				case "id":
					id = Long.parseLong(value);
					break;

				case "timestamp":
					timestamp = LocalDateTime.parse(value, FORMATTER);
					break;

				case "co2":
					co2 = Double.parseDouble(value);
					break;
				case "co":
					co = Double.parseDouble(value);
					break;
				case "no2":
					no2 = Double.parseDouble(value);
					break;
				case "so2":
					so2 = Double.parseDouble(value);
					break;
				case "pm25":
					pm25 = Double.parseDouble(value);
					break;
				case "pm10":
					pm10 = Double.parseDouble(value);
					break;
				case "umidade":
					umidade = Double.parseDouble(value);
					break;
				case "temperatura":
					temperatura = Double.parseDouble(value);
					break;
				case "ruido":
					ruido = Double.parseDouble(value);
					break;
				case "radiacao":
					radiacao = Double.parseDouble(value);
					break;
				}
			}

			return new ClimateData(id, timestamp, co2, co, no2, so2, pm25, pm10, umidade, temperatura, ruido, radiacao);

		} catch (Exception e) {
			System.out.println("❌ Erro ao parsear: " + line);
			e.printStackTrace();
			return null;
		}
	}

}