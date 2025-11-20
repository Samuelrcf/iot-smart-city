package server;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter; // Importação necessária

public class ClimateData {
	private Long id;
	private LocalDateTime timestamp;
	private double co2, co, no2, so2, pm25, pm10, umidade, temperatura, ruido, radiacao;

	// Define um formatador estático e final para eficiência
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

	// [Getters e Setters omitidos para brevidade]

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
        
		return "Dados Climáticos [id=" + id 
				+ ", timestamp=" + formattedTimestamp + ", co2=" + String.format("%.2f", co2)
                + ", co=" + String.format("%.2f", co)
                + ", no2=" + String.format("%.2f", no2)
				+ ", so2=" + String.format("%.2f", so2) 
				+ ", pm25=" + String.format("%.2f", pm25)
				+ ", pm10=" + String.format("%.2f", pm10)
				+ ", umidade=" + String.format("%.2f", umidade) 
				+ ", temperatura=" + String.format("%.2f", temperatura)
				+ ", ruido=" + String.format("%.2f", ruido)
				+ ", radiacao=" + String.format("%.2f", radiacao) + "]";
	}

}