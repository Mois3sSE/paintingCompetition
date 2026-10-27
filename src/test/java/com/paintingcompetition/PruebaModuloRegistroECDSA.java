
package com.paintingcompetition;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;

import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloRegistroECDSA;

public class PruebaModuloRegistroECDSA {

    public static void main(String[] args) {

        ModuloRegistroECDSA modulo = new ModuloRegistroECDSA();

        System.out.println("======================================");
        System.out.println("  MODULO DE AUTENTICIDAD - ECDSA");
        System.out.println("  INTEGRANTE 2");
        System.out.println("======================================");

        // 1. Generar llaves del pintor.
        KeyPair llaves = modulo.generarParLlavesECDSA();

        System.out.println("\n[1] GENERACION DE LLAVES");
        System.out.println("Algoritmo: " + llaves.getPublic().getAlgorithm());
        System.out.println("Curva: secp256r1");
        System.out.println("Llaves generadas correctamente.");

        // 2. Preparar los datos del registro.
        String registro =
                "PINTOR:Eduardo|OBRA:pintura01.png|REGISTRO:001";

        byte[] mensaje = registro.getBytes(StandardCharsets.UTF_8);

        // 3. Firmar con la llave privada.
        byte[] firma = modulo.firmar(
                mensaje,
                llaves.getPrivate()
        );

        System.out.println("\n[2] FIRMA DIGITAL");
        System.out.println("Registro: " + registro);
        System.out.println("Firma generada: " + firma.length + " bytes");

        // 4. Verificar firma original.
        boolean valida = modulo.verificarFirmaECDSA(
                mensaje,
                firma,
                llaves.getPublic()
        );

        System.out.println("\n[3] VERIFICACION ORIGINAL");
        System.out.println("Firma valida: " + valida);

        // 5. Modificar el registro despues de firmarlo.
        byte[] alterado = (
                "PINTOR:Eduardo|OBRA:pintura02.png|REGISTRO:001"
        ).getBytes(StandardCharsets.UTF_8);

        boolean validaAlterada = modulo.verificarFirmaECDSA(
                alterado,
                firma,
                llaves.getPublic()
        );

        System.out.println("\n[4] MENSAJE MODIFICADO");
        System.out.println("Firma valida: " + validaAlterada);

        // 6. Verificar con otra llave publica.
        KeyPair otrasLlaves = modulo.generarParLlavesECDSA();

        boolean validaOtraLlave = modulo.verificarFirmaECDSA(
                mensaje,
                firma,
                otrasLlaves.getPublic()
        );

        System.out.println("\n[5] LLAVE PUBLICA INCORRECTA");
        System.out.println("Firma valida: " + validaOtraLlave);

        // 7. Alterar los bytes de la firma.
        byte[] firmaAlterada = Arrays.copyOf(
                firma, firma.length
        );

        firmaAlterada[firmaAlterada.length - 1] ^= 0x01;

        boolean validaFirmaAlterada = modulo.verificarFirmaECDSA(
                mensaje,
                firmaAlterada,
                llaves.getPublic()
        );

        System.out.println("\n[6] FIRMA MODIFICADA");
        System.out.println("Firma valida: " + validaFirmaAlterada);

        // 8. Comprobar los resultados.
        if (valida
                && !validaAlterada
                && !validaOtraLlave
                && !validaFirmaAlterada) {

            System.out.println("\nTODAS LAS PRUEBAS PASARON.");

        } else {

            throw new IllegalStateException(
                    "Una o mas pruebas ECDSA fallaron."
            );
        }
    }
}
