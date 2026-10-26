package com.paintingcompetition.infrastructure.adapters.out.crypto;

import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.engines.RSAEngine;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Generación del factor de cegado, cegado de mensajes y
 * protocolo de firma ciega RSA (Chaum).
 */
public class ModuloAnonimatoRSA implements MotorCriptograficoPort {

    @Override
    public byte[] cifrar(byte[] datos, Object clave) {
        throw new UnsupportedOperationException("El modulo de Anonimato no realiza la opreacion de cifrar.");
    }

    @Override
    public byte[] firmar(byte[] datos, Object clavePrivada) {
        return firmarCegadoRSA(datos, (RSAPrivateKey) clavePrivada);
    }

    @Override
    public byte[] cegar(byte[] datos, Object clavePublica) {
        RSAPublicKey llavePub = (RSAPublicKey) clavePublica;
        BigInteger factor = generarFactorCegado(llavePub);
        return cegarMensaje(datos, factor, llavePub);
    }

    public KeyPair generarParLlavesRSA() {
        try {
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(3072);
            return generador.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error al generar llaves.");
        }
    }

    public BigInteger generarFactorCegado(RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());

            RSABlindingFactorGenerator generadorFactor = new RSABlindingFactorGenerator();
            SecureRandom randomSeguro = new SecureRandom();
            generadorFactor.init(new ParametersWithRandom(llavePublicaBC, randomSeguro));
            return generadorFactor.generateBlindingFactor();

        } catch (Exception e) {
            throw new RuntimeException("Error al general el factor de cegado.");
        }

    }

    public byte[] cegarMensaje(byte[] mensaje, BigInteger factorCegado, RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());
            RSABlindingParameters parametrosCegado = new RSABlindingParameters(llavePublicaBC, factorCegado);
            RSABlindingEngine motorCegado = new RSABlindingEngine();
            motorCegado.init(true, parametrosCegado);
            return motorCegado.processBlock(mensaje, 0, mensaje.length);
        } catch (Exception e) {
            throw new RuntimeException("Error al cegar el mensaje.");
        }
    }

    public byte[] firmarCegadoRSA(byte[] mensajeCegado, RSAPrivateKey clavePrivadaRSA) {
        try {
            RSAKeyParameters llavePrivadaBC = new RSAKeyParameters(true,
                    clavePrivadaRSA.getModulus(),
                    clavePrivadaRSA.getPrivateExponent());

            RSAEngine motorRSA = new RSAEngine();
            motorRSA.init(true, llavePrivadaBC);
            return motorRSA.processBlock(mensajeCegado, 0, mensajeCegado.length);

        } catch (Exception e) {
            throw new RuntimeException("Error al aplicar la firma al mensaje");
        }
    }

    public byte[] descegarFirmaRSA(byte[] firmaCegada, BigInteger factorCegado, RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());

            RSABlindingParameters parametrosCegado = new RSABlindingParameters(llavePublicaBC, factorCegado);
            RSABlindingEngine motorCegado = new RSABlindingEngine();
            motorCegado.init(false, parametrosCegado);
            return motorCegado.processBlock(firmaCegada, 0, firmaCegada.length);
        } catch (Exception e) {
            throw new RuntimeException("Error al descegar la firma.");
        }
    }

    public boolean verificarFirmaRSA(byte[] mensajeOriginal, byte[] firmaDescegada, RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());
                    
            RSAEngine motorRSA = new RSAEngine();
            motorRSA.init(true, llavePublicaBC);
            byte[] mensajeRecuperado = motorRSA.processBlock(firmaDescegada, 0, firmaDescegada.length);
            return Arrays.equals(limpiarCeros(mensajeRecuperado), limpiarCeros(mensajeOriginal));
        } catch (Exception e) {
            System.err.println("Error en la verificacion de firma: " + e.getMessage());
            return false;
        }

    }

    private byte[] limpiarCeros(byte[] arreglo) {
        int i = 0;
        while (i < arreglo.length && arreglo[i] == 0) {
            i++;
        }
        return Arrays.copyOfRange(arreglo, i, arreglo.length);
    }
}
