package com.paintingcompetition.infrastructure.adapters.out.io;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.paintingcompetition.domain.ports.out.GestorArchivosActaPort;
import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloFirmaRSAPSS;

public class GestorArchivosActaAdapter implements GestorArchivosActaPort {

    private final MotorCriptograficoPort motorFirma;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public GestorArchivosActaAdapter() {
        this.motorFirma = new ModuloFirmaRSAPSS();
    }

    public GestorArchivosActaAdapter(MotorCriptograficoPort motorFirma) {
        this.motorFirma = Objects.requireNonNull(motorFirma, "El motor criptográfico de firma no puede ser nulo.");
    }

    @Override
    public void guardarLlavePublicaBase64(PublicKey clavePublica, String rutaArchivo) throws IOException {
        Objects.requireNonNull(clavePublica, "La clave pública no puede ser nula.");
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");

        byte[] encoded = clavePublica.getEncoded();
        String b64 = Base64.getEncoder().encodeToString(encoded);

        Path path = Paths.get(rutaArchivo);
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }
        Files.writeString(path, b64, StandardCharsets.UTF_8);
    }

    @Override
    public void guardarLlavePrivadaBase64(PrivateKey clavePrivada, String rutaArchivo) throws IOException {
        Objects.requireNonNull(clavePrivada, "La clave privada no puede ser nula.");
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");

        byte[] encoded = clavePrivada.getEncoded();
        String b64 = Base64.getEncoder().encodeToString(encoded);

        Path path = Paths.get(rutaArchivo);
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }
        Files.writeString(path, b64, StandardCharsets.UTF_8);
    }

    @Override
    public void guardarParLlavesBase64(KeyPair parLlaves, String rutaPublica, String rutaPrivada) throws IOException {
        Objects.requireNonNull(parLlaves, "El par de llaves no puede ser nulo.");
        guardarLlavePublicaBase64(parLlaves.getPublic(), rutaPublica);
        guardarLlavePrivadaBase64(parLlaves.getPrivate(), rutaPrivada);
    }

    @Override
    public PublicKey cargarLlavePublicaBase64(String rutaArchivo) throws Exception {
        Path path = Paths.get(rutaArchivo);
        if (!Files.exists(path)) {
            throw new IOException("El archivo de clave pública no existe: " + rutaArchivo);
        }

        String contenidoB64 = Files.readString(path, StandardCharsets.UTF_8).trim();
        byte[] bytesClave = Base64.getDecoder().decode(contenidoB64);

        KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesClave);
        return kf.generatePublic(spec);
    }

    @Override
    public PrivateKey cargarLlavePrivadaBase64(String rutaArchivo) throws Exception {
        Path path = Paths.get(rutaArchivo);
        if (!Files.exists(path)) {
            throw new IOException("El archivo de clave privada no existe: " + rutaArchivo);
        }

        String contenidoB64 = Files.readString(path, StandardCharsets.UTF_8).trim();
        byte[] bytesClave = Base64.getDecoder().decode(contenidoB64);

        KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytesClave);
        return kf.generatePrivate(spec);
    }

    @Override
    public byte[] leerDocumentoActa(String rutaArchivo) throws IOException {
        Path path = Paths.get(rutaArchivo);
        if (!Files.exists(path)) {
            throw new IOException("El archivo del acta no fue encontrado en la ruta: " + rutaArchivo);
        }
        return Files.readAllBytes(path);
    }

    @Override
    public String firmarActaYRetornarBase64(String rutaDocumentoActa, PrivateKey clavePrivada) throws IOException {
        byte[] datosActa = leerDocumentoActa(rutaDocumentoActa);
        byte[] firmaDigital = motorFirma.firmar(datosActa, clavePrivada);
        return Base64.getEncoder().encodeToString(firmaDigital);
    }

    @Override
    public boolean verificarFirmaActa(String rutaDocumentoActa, String firmaBase64, PublicKey clavePublica)
            throws IOException {
        byte[] datosActa = leerDocumentoActa(rutaDocumentoActa);
        byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64.trim());
        return motorFirma.verificar(datosActa, firmaBytes, clavePublica);
    }
}
