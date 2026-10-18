
package com.paintingcompetition.domain.ports.out;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Puerto especializado para las operaciones de autenticidad ECDSA.
 * Integrante 2 - Modulo de Registro.
 *
 * Permite utilizar el modulo ECDSA sin depender
 * directamente de su adaptador de infraestructura.
 */
public interface RegistroECDSAPort extends MotorCriptograficoPort {

    // Generacion de llaves ECDSA
    KeyPair generarParLlavesECDSA();

    // Firma digital del registro
    byte[] firmarECDSA(byte[] mensaje, PrivateKey clavePrivada);

    // Verificacion de firma digital
    boolean verificarFirmaECDSA(
            byte[] mensaje,
            byte[] firma,
            PublicKey clavePublica
    );
}
