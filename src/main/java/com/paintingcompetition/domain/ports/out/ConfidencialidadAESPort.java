package com.paintingcompetition.domain.ports.out;

import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * Puerto especializado para las operaciones de confidencialidad AES y acuerdo de claves ECDH.
 * Integrante 1 - Módulo de Confidencialidad.
 */
public interface ConfidencialidadAESPort extends MotorCriptograficoPort {

    SecretKey generarClaveAES(int longitudBits);

    byte[] generarIV(int longitudBytes);

    byte[] cifrarAES_GCM(byte[] datosEnClaro, SecretKey claveSecreta, byte[] iv);

    byte[] descifrarAES_GCM(byte[] datosCifrados, SecretKey claveSecreta, byte[] iv);

    byte[] derivarClaveCompartidaECDH(PrivateKey clavePrivadaLocal, PublicKey clavePublicaRemota);

    SecretKey derivarClaveAES(PrivateKey clavePrivadaLocal, PublicKey clavePublicaRemota);
}

