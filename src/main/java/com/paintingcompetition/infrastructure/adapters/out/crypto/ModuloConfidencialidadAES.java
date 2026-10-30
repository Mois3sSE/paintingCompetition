package com.paintingcompetition.infrastructure.adapters.out.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.paintingcompetition.domain.ports.out.ConfidencialidadAESPort;

import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;

/**
 * Adaptador de Salida para Confidencialidad y Acuerdo de Claves.
 * Asignado a: INTEGRANTE 1.
 * Responsabilidad: Cifrado autenticado con AES-GCM y derivación de secretos
 * compartidos con ECDH.
 */
public class ModuloConfidencialidadAES implements ConfidencialidadAESPort {

    private static final String ALGORITMO_AES = "AES";
    private static final String TRANSFORMACION_AES_GCM = "AES/GCM/NoPadding";
    private static final int LONGITUD_TAG_GCM_BITS = 128; // Tamaño estándar del tag de autenticación
    private static final String ALGORITMO_ECDH = "ECDH";
    private static final String CURVA_EC = "secp256r1"; // Curva estándar NIST P-256

    // =========================================================================
    // IMPLEMENTACIÓN DEL PUERTO GENÉRICO (MotorCriptograficoPort)
    // =========================================================================

    @Override
    public byte[] cifrar(byte[] datos, Object clave) {
        try {
            if (!(clave instanceof SecretKey)) {
                throw new IllegalArgumentException(
                        "La clave provista para el cifrado debe ser una instancia de SecretKey (AES)");
            }
            SecretKey claveSecreta = (SecretKey) clave;

            // Generamos un IV estándar para GCM (12 bytes / 96 bits)
            byte[] iv = generarIV(12);

            // Ciframos los datos
            byte[] datosCifrados = cifrarAES_GCM(datos, claveSecreta, iv);

            // Concatenamos el IV al inicio del payload cifrado [IV (12 bytes) + DATOS
            // CIFRADOS]
            // Esto permite que quien descifre pueda recuperar el IV fácilmente
            byte[] resultadoConIV = new byte[iv.length + datosCifrados.length];
            System.arraycopy(iv, 0, resultadoConIV, 0, iv.length);
            System.arraycopy(datosCifrados, 0, resultadoConIV, iv.length, datosCifrados.length);

            return resultadoConIV;

        } catch (Exception e) {
            throw new RuntimeException("Error durante el proceso de cifrado en ModuloConfidencialidadAES", e);
        }
    }

    @Override
    public byte[] firmar(byte[] datos, Object clavePrivada) {
        // Corresponde a Integrante 2 (ModuloRegistroECDSA)
        throw new UnsupportedOperationException(
                "La firma criptográfica ECDSA no es responsabilidad del Integrante 1 (ModuloConfidencialidadAES)");
    }

    @Override
    public byte[] cegar(byte[] datos, Object clavePublica) {
        // Corresponde a Integrante 3 (ModuloAnonimatoRSA)
        throw new UnsupportedOperationException(
                "El cegado RSA de votos no es responsabilidad del Integrante 1 (ModuloConfidencialidadAES)");
    }

    // =========================================================================
    // MÉTODOS ESPECÍFICOS - INTEGRANTE 1: AES-GCM y ECDH
    // =========================================================================

    /**
     * Genera una clave simétrica AES segura (ej. 128 o 256 bits).
     */
    public SecretKey generarClaveAES(int longitudBits) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITMO_AES);
            keyGen.init(longitudBits);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error al generar clave simétrica AES", e);
        }
    }

    /**
     * Genera un Vector de Inicialización (IV) criptográficamente seguro
     * (típicamente 12 bytes para GCM).
     */
    public byte[] generarIV(int longitudBytes) {
        byte[] iv = new byte[longitudBytes];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Cifra datos en claro utilizando el modo AES-GCM (cifrado autenticado).
     */
    public byte[] cifrarAES_GCM(byte[] datosEnClaro, SecretKey claveSecreta, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACION_AES_GCM);
            GCMParameterSpec spec = new GCMParameterSpec(LONGITUD_TAG_GCM_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, claveSecreta, spec);
            return cipher.doFinal(datosEnClaro);
        } catch (Exception e) {
            throw new RuntimeException("Error al cifrar datos con AES-GCM", e);
        }
    }

    /**
     * Descifra datos cifrados con AES-GCM verificando su tag de autenticación.
     */
    public byte[] descifrarAES_GCM(byte[] datosCifrados, SecretKey claveSecreta, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACION_AES_GCM);
            GCMParameterSpec spec = new GCMParameterSpec(LONGITUD_TAG_GCM_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, claveSecreta, spec);
            return cipher.doFinal(datosCifrados);
        } catch (Exception e) {
            throw new RuntimeException("Error o fallo de integridad/autenticidad al descifrar con AES-GCM", e);
        }
    }

    /**
     * Genera un par de llaves (pública y privada) para el protocolo Elliptic Curve
     * Diffie-Hellman (ECDH).
     */
    public KeyPair generarParLlavesECDH() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVA_EC);
            keyPairGen.initialize(ecSpec, new SecureRandom());
            return keyPairGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error al generar el par de llaves ECDH con la curva " + CURVA_EC, e);
        }
    }

    /**
     * Deriva un secreto compartido utilizando la llave privada local y la llave
     * pública remota mediante ECDH.
     */
    public byte[] derivarClaveCompartidaECDH(PrivateKey clavePrivadaLocal, PublicKey clavePublicaRemota) {
        try {
            KeyAgreement keyAgreement;
            if (java.security.Security.getProvider("BC") != null) {
                try {
                    keyAgreement = KeyAgreement.getInstance(ALGORITMO_ECDH, "BC");
                } catch (Exception e) {
                    keyAgreement = KeyAgreement.getInstance(ALGORITMO_ECDH);
                }
            } else {
                keyAgreement = KeyAgreement.getInstance(ALGORITMO_ECDH);
            }
            keyAgreement.init(clavePrivadaLocal);
            keyAgreement.doPhase(clavePublicaRemota, true);

            // Generar el secreto compartido en bytes brutos
            byte[] secretoCompartido = keyAgreement.generateSecret();

            // Pasamos el secreto por SHA-256 (KDF simple) para derivar un bloque limpio de
            // 256 bits (32 bytes)
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(secretoCompartido);

        } catch (Exception e) {
            throw new RuntimeException("Error al derivar el secreto compartido mediante ECDH", e);
        }
    }

    /**
     * Deriva una clave simétrica SecretKey (AES-256) a partir del acuerdo de claves
     * ECDH.
     */
    @Override
    public SecretKey derivarClaveAES(PrivateKey clavePrivadaLocal, PublicKey clavePublicaRemota) {
        byte[] bytesClave = derivarClaveCompartidaECDH(clavePrivadaLocal, clavePublicaRemota);
        return new SecretKeySpec(bytesClave, ALGORITMO_AES);
    }
}
