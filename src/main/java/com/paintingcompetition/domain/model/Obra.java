package com.paintingcompetition.domain.model;

import java.util.Arrays;

/**
 * Entidad de Dominio que representa una Obra de pintura registrada en el
 * concurso.
 */
public class Obra {

    private String id;
    private String titulo;
    private String descripcion;
    private String autorId;

    // Campos criptográficos asociados a la obra
    private byte[] contenidoCifrado;
    private byte[] ivCifrado;
    private byte[] firmaDigitalECDSA;
    private byte[] firmaCegadaRSA;
    private byte[] tokenAnonimo;

    public Obra() {
    }

    public Obra(String id, String titulo, String descripcion, String autorId) {
        this.id = id;
        this.titulo = titulo;
        this.descripcion = descripcion;
        this.autorId = autorId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitulo() {
        return titulo;
    }

    public void setTitulo(String titulo) {
        this.titulo = titulo;
    }

    public String getDescripcion() {
        return descripcion;
    }

    public void setDescripcion(String descripcion) {
        this.descripcion = descripcion;
    }

    public String getAutorId() {
        return autorId;
    }

    public void setAutorId(String autorId) {
        this.autorId = autorId;
    }

    public byte[] getContenidoCifrado() {
        return contenidoCifrado;
    }

    public void setContenidoCifrado(byte[] contenidoCifrado) {
        this.contenidoCifrado = contenidoCifrado;
    }

    public byte[] getIvCifrado() {
        return ivCifrado;
    }

    public void setIvCifrado(byte[] ivCifrado) {
        this.ivCifrado = ivCifrado;
    }

    public byte[] getFirmaDigitalECDSA() {
        return firmaDigitalECDSA;
    }

    public void setFirmaDigitalECDSA(byte[] firmaDigitalECDSA) {
        this.firmaDigitalECDSA = firmaDigitalECDSA;
    }

    public byte[] getFirmaCegadaRSA() {
        return firmaCegadaRSA;
    }

    public void setFirmaCegadaRSA(byte[] firmaCegadaRSA) {
        this.firmaCegadaRSA = firmaCegadaRSA;
    }

    public byte[] getTokenAnonimo() {
        return tokenAnonimo;
    }

    public void setTokenAnonimo(byte[] tokenAnonimo) {
        this.tokenAnonimo = tokenAnonimo;
    }

    @Override
    public String toString() {
        return "Obra{" +
                "id='" + id + '\'' +
                ", titulo='" + titulo + '\'' +
                ", descripcion='" + descripcion + '\'' +
                ", autorId='" + autorId + '\'' +
                ", tieneContenidoCifrado=" + (contenidoCifrado != null) +
                ", tieneFirmaECDSA=" + (firmaDigitalECDSA != null) +
                ", tieneFirmaRSA=" + (firmaCegadaRSA != null) +
                '}';
    }
}
