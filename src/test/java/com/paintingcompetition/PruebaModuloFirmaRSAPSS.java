package com.paintingcompetition;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import com.paintingcompetition.domain.model.ActaResultados;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloFirmaRSAPSS;
import com.paintingcompetition.infrastructure.adapters.out.io.GestorArchivosActaAdapter;

/**
 * Pruebas unitarias de integración para el esquema de firmas RSASSA-PSS (FIPS
 * 186-5)
 * y el componente de E/S para el Acta de Resultados del Presidente.
 */
public class PruebaModuloFirmaRSAPSS {

    public static void main(String[] args) {
        try {
            System.out.println("==============================================================");
            System.out.println(" PRUEBA DEL MÓDULO DE FIRMAS RSASSA-PSS (FIPS 186-5) - BC");
            System.out.println("==============================================================");

            ModuloFirmaRSAPSS moduloPSS = new ModuloFirmaRSAPSS();
            GestorArchivosActaAdapter gestorIO = new GestorArchivosActaAdapter(moduloPSS);

            // 1. Generación de llaves RSASSA-PSS (3072 bits, FIPS 186-5)
            System.out.println("\n[1] GENERACIÓN DE LLAVES RSA-PSS (3072 bits)");
            KeyPair parLlaves = moduloPSS.generarParLlaves();
            RSAPublicKey pubKey = (RSAPublicKey) parLlaves.getPublic();

            System.out.println("Algoritmo de Clave: " + pubKey.getAlgorithm());
            System.out.println("Tamaño de Clave: " + pubKey.getModulus().bitLength() + " bits");
            System.out.println("Exponente Público e: " + pubKey.getPublicExponent() + " (FIPS e >= 65537: "
                    + (pubKey.getPublicExponent().intValue() >= 65537) + ")");

            if (pubKey.getModulus().bitLength() < 2048) {
                throw new IllegalStateException(
                        "Falla de conformidad FIPS 186-5: longitud de clave menor a 2048 bits.");
            }

            // 2. Persistencia en Base64 con nombres definidos por el usuario
            System.out.println("\n[2] PERSISTENCIA DE LLAVES EN BASE64");
            Path tempDir = Files.createTempDirectory("crypto_pss_test");
            String rutaPub = tempDir.resolve("clave_publica_presidente.txt").toString();
            String rutaPriv = tempDir.resolve("clave_privada_presidente.txt").toString();

            gestorIO.guardarParLlavesBase64(parLlaves, rutaPub, rutaPriv);
            System.out.println("Clave pública exportada a: " + rutaPub);
            System.out.println("Clave privada exportada a: " + rutaPriv);

            // Cargar y reconstruir las llaves para comprobar deserialización Base64
            PublicKey pubRecuperada = gestorIO.cargarLlavePublicaBase64(rutaPub);
            PrivateKey privRecuperada = gestorIO.cargarLlavePrivadaBase64(rutaPriv);
            System.out.println("✓ Ambas claves cargadas y reconstruidas exitosamente desde Base64.");

            // 3. Creación y Firma del Acta de Resultados en texto plano
            System.out.println("\nEMISIÓN Y FIRMA DE ACTA DE RESULTADOS");
            String textoActa = "====================================================\n"
                    + " ACTA DE RESULTADOS OFICIAL - CONCURSO DE PINTURA 2026\n"
                    + " EMISOR: Presidente del Comité Organizador\n"
                    + "====================================================\n"
                    + "1er Lugar: 'Amanecer en el Valle' - Promedio: 3★\n"
                    + "2do Lugar: 'Sombras de Otoño'     - Promedio: 2★\n"
                    + "3er Lugar: 'Horizonte Azul'      - Promedio: 1★\n"
                    + "Certificación: Resultados inalterables y definitivos.\n";

            String rutaActa = tempDir.resolve("acta_resultados_final.txt").toString();
            Files.writeString(Path.of(rutaActa), textoActa, StandardCharsets.UTF_8);
            System.out.println("Documento de Acta creado en: " + rutaActa);

            String firmaBase64 = gestorIO.firmarActaYRetornarBase64(rutaActa, privRecuperada);
            System.out.println("Firma RSASSA-PSS generada (Base64):\n" + firmaBase64);

            ActaResultados actaEntidad = new ActaResultados(rutaActa,
                    java.util.Base64.getDecoder().decode(firmaBase64));
            System.out.println("Entidad de Dominio ActaResultados vinculada: " + actaEntidad);

            System.out.println("\nVERIFICACIÓN DE FIRMA DIGITAL");
            boolean esValida = gestorIO.verificarFirmaActa(rutaActa, firmaBase64, pubRecuperada);
            System.out.println("Resultado de verificación del Acta original: " + esValida);
            if (!esValida) {
                throw new IllegalStateException("La firma digital RSASSA-PSS del documento original falló.");
            }

            // 5. Verificación de no repudio / detección de fraude (alteración del
            // documento)
            System.out.println("\n[5] PRUEBA DE RESISTENCIA A MANIPULACIÓN (DETECCIÓN DE FRAUDE)");
            String textoAlterado = textoActa.replace("Amanecer en el Valle", "Obra Alterada Fraudulenta");
            String rutaActaAlterada = tempDir.resolve("acta_resultados_alterada.txt").toString();
            Files.writeString(Path.of(rutaActaAlterada), textoAlterado, StandardCharsets.UTF_8);

            boolean esValidaAlterada = gestorIO.verificarFirmaActa(rutaActaAlterada, firmaBase64, pubRecuperada);
            System.out.println("Resultado de verificación con documento alterado: " + esValidaAlterada);
            if (esValidaAlterada) {
                throw new IllegalStateException("Falla de seguridad: La firma no detectó la alteración del documento.");
            }

            System.out.println("✓ Modificación detectada con éxito (firma rechazada).");

            System.out.println("\n==============================================================");
            System.out.println(" [OK] TODAS LAS PRUEBAS DE RSASSA-PSS (FIPS 186-5) PASARON.");
            System.out.println("==============================================================");

        } catch (Exception e) {
            System.err.println("[!] Error durante la prueba: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
