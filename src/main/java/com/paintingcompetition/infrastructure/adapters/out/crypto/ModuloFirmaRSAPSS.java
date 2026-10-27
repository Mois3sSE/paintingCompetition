package com.paintingcompetition.infrastructure.adapters.out.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Objects;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.paintingcompetition.domain.ports.out.GestorLlavesPort;
import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;

public class ModuloFirmaRSAPSS implements MotorCriptograficoPort, GestorLlavesPort {

    public static final String PROVEEDOR_BC = BouncyCastleProvider.PROVIDER_NAME;
    public static final String ALGORITMO_FIRMA = "SHA256withRSA/PSS";
    public static final String HASH_ALGORITMO = "SHA-256";
    public static final String MGF_ALGORITMO = "MGF1";
    public static final int LONGITUD_SALT_BYTES = 32;
    public static final int LONGITUD_LLAVE_DEFAULT_BITS = 3072;

    private final PSSParameterSpec pssParameterSpec;

    static {
        if (Security.getProvider(PROVEEDOR_BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public ModuloFirmaRSAPSS() {
        // Configuración de parámetros PSS conforme a FIPS 186-5 y RFC 8017
        this.pssParameterSpec = new PSSParameterSpec(
                HASH_ALGORITMO,
                MGF_ALGORITMO,
                MGF1ParameterSpec.SHA256,
                LONGITUD_SALT_BYTES,
                PSSParameterSpec.TRAILER_FIELD_BC);
    }

    @Override
    public KeyPair generarParLlaves() {
        return generarParLlaves(LONGITUD_LLAVE_DEFAULT_BITS);
    }

    @Override
    public KeyPair generarParLlaves(int longitudBits) {
        if (longitudBits < 2048) {
            throw new IllegalArgumentException(
                    "FIPS 186-5 requiere longitudes de módulo RSA de al menos 2048 bits (recomendado 3072 bits).");
        }

        try {
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA", PROVEEDOR_BC);
            // e = 65537 (F4) exigido por FIPS 186-5
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(longitudBits, RSAKeyGenParameterSpec.F4);
            generador.initialize(spec, new SecureRandom());
            return generador.generateKeyPair();

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error al generar el par de llaves RSA-PSS con Bouncy Castle", e);
        }
    }

    @Override
    public byte[] firmar(byte[] datos, Object clavePrivada) {
        Objects.requireNonNull(datos, "Los datos a firmar no pueden ser nulos.");
        Objects.requireNonNull(clavePrivada, "La clave privada no puede ser nula.");

        if (!(clavePrivada instanceof PrivateKey)) {
            throw new IllegalArgumentException("Se requiere una instancia válida de PrivateKey para firmar.");
        }

        try {
            Signature firmador = Signature.getInstance(ALGORITMO_FIRMA, PROVEEDOR_BC);
            firmador.setParameter(this.pssParameterSpec);
            firmador.initSign((PrivateKey) clavePrivada, new SecureRandom());
            firmador.update(datos);
            return firmador.sign();

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error al generar la firma digital RSASSA-PSS: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verificar(byte[] datos, byte[] firma, Object clave) {
        Objects.requireNonNull(datos, "Los datos originales no pueden ser nulos.");
        Objects.requireNonNull(firma, "La firma a verificar no puede ser nula.");
        Objects.requireNonNull(clave, "La clave pública no puede ser nula.");

        if (!(clave instanceof PublicKey)) {
            throw new IllegalArgumentException("Se requiere una instancia válida de PublicKey para verificar.");
        }

        try {
            Signature verificador = Signature.getInstance(ALGORITMO_FIRMA, PROVEEDOR_BC);
            verificador.setParameter(this.pssParameterSpec);
            verificador.initVerify((PublicKey) clave);
            verificador.update(datos);
            return verificador.verify(firma);

        } catch (SignatureException e) {
            // Firma corrupta o formato inválido
            return false;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error al verificar la firma digital RSASSA-PSS: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] cifrar(byte[] datos, Object clave) {
        throw new UnsupportedOperationException(
                "El módulo RSASSA-PSS está destinado exclusivamente a firmas digitales.");
    }

    @Override
    public byte[] cegar(byte[] datos, Object clavePublica) {
        throw new UnsupportedOperationException("El cegado de mensajes no corresponde al módulo RSASSA-PSS.");
    }
}
