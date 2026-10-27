package com.paintingcompetition.domain.model;

import java.util.Arrays;
import java.util.Base64;

/**
 * Entidad de Dominio que representa el Acta de Resultados oficial del concurso,
 * emitida en texto plano por el Presidente y respaldada por una firma digital RSASSA-PSS
 * en conformidad con el estándar FIPS 186-5.
 */
public class ActaResultados {

    private String id;
    private String rutaArchivoTexto;
    private byte[] firmaDigital;
    private String firmaDigitalBase64;
    private String emisorRol;
    private long timestampEmision;

    public ActaResultados() {
        this.emisorRol = "PRESIDENTE";
        this.timestampEmision = System.currentTimeMillis();
    }

    public ActaResultados(String rutaArchivoTexto, byte[] firmaDigital) {
        this();
        this.rutaArchivoTexto = rutaArchivoTexto;
        this.firmaDigital = firmaDigital;
        if (firmaDigital != null) {
            this.firmaDigitalBase64 = Base64.getEncoder().encodeToString(firmaDigital);
        }
    }

    public ActaResultados(String id, String rutaArchivoTexto, byte[] firmaDigital, String emisorRol) {
        this.id = id;
        this.rutaArchivoTexto = rutaArchivoTexto;
        this.firmaDigital = firmaDigital;
        if (firmaDigital != null) {
            this.firmaDigitalBase64 = Base64.getEncoder().encodeToString(firmaDigital);
        }
        this.emisorRol = emisorRol != null ? emisorRol : "PRESIDENTE";
        this.timestampEmision = System.currentTimeMillis();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRutaArchivoTexto() {
        return rutaArchivoTexto;
    }

    public void setRutaArchivoTexto(String rutaArchivoTexto) {
        this.rutaArchivoTexto = rutaArchivoTexto;
    }

    public byte[] getFirmaDigital() {
        return firmaDigital;
    }

    public void setFirmaDigital(byte[] firmaDigital) {
        this.firmaDigital = firmaDigital;
        if (firmaDigital != null) {
            this.firmaDigitalBase64 = Base64.getEncoder().encodeToString(firmaDigital);
        } else {
            this.firmaDigitalBase64 = null;
        }
    }

    public String getFirmaDigitalBase64() {
        return firmaDigitalBase64;
    }

    public void setFirmaDigitalBase64(String firmaDigitalBase64) {
        this.firmaDigitalBase64 = firmaDigitalBase64;
        if (firmaDigitalBase64 != null && !firmaDigitalBase64.trim().isEmpty()) {
            this.firmaDigital = Base64.getDecoder().decode(firmaDigitalBase64.trim());
        } else {
            this.firmaDigital = null;
        }
    }

    public String getEmisorRol() {
        return emisorRol;
    }

    public void setEmisorRol(String emisorRol) {
        this.emisorRol = emisorRol;
    }

    public long getTimestampEmision() {
        return timestampEmision;
    }

    public void setTimestampEmision(long timestampEmision) {
        this.timestampEmision = timestampEmision;
    }

    @Override
    public String toString() {
        return "ActaResultados{" +
                "id='" + id + '\'' +
                ", rutaArchivoTexto='" + rutaArchivoTexto + '\'' +
                ", tieneFirmaDigital=" + (firmaDigital != null) +
                ", emisorRol='" + emisorRol + '\'' +
                ", timestampEmision=" + timestampEmision +
                '}';
    }
}
