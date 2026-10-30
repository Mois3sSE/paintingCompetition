package com.paintingcompetition;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKey;

import com.paintingcompetition.domain.model.RolUsuario;
import com.paintingcompetition.domain.model.Usuario;
import com.paintingcompetition.infrastructure.adapters.in.console.MenuPrincipalConsola;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloAnonimatoRSA;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloConfidencialidadAES;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloRegistroECDSA;

/**
 * Verificación Integral de Flujo Criptográfico:
 * 1. Derivación de clave simétrica AES mediante ECDH (d_pintor * Q_sistema).
 * 2. Cifrado AES-GCM conservando la extensión original (Opción A).
 * 3. Hash matemático SHA-256 de la obra cifrada.
 * 4. Firma digital ECDSA usando la llave privada del pintor en
 * claves_usuario/pintores/<NombreUsuario>.
 * 5. Verificación de la firma digital con la llave pública del pintor.
 * 6. Detección de alteración o fraude.
 */
public class PruebaFirmaObraCifradaECDSA {

    public static void main(String[] args) {
        System.out.println("==============================================================");
        System.out.println(" INICIANDO TEST: CIFRADO (OPCIÓN A) Y FIRMA DIGITAL ECDSA");
        System.out.println("==============================================================");

        try {
            ModuloConfidencialidadAES moduloAES = new ModuloConfidencialidadAES();
            ModuloRegistroECDSA moduloECDSA = new ModuloRegistroECDSA();
            ModuloAnonimatoRSA moduloRSA = new ModuloAnonimatoRSA();
            MenuPrincipalConsola consola = new MenuPrincipalConsola(moduloAES, moduloECDSA, moduloRSA);

            String nombrePintor = "davinci";
            Usuario pintor = new Usuario("user-davinci-id", nombrePintor, RolUsuario.PINTOR);

            // 1. Inicializar llaves del sistema y del pintor
            Path dirClavesPintor = Paths.get("claves_usuario", "pintores", nombrePintor);
            consola.inicializarLlavesPintor(pintor);

            Path pathPubPintor = dirClavesPintor.resolve("pub_" + nombrePintor + ".txt");
            Path pathPrivPintor = dirClavesPintor.resolve("priv_" + nombrePintor + ".txt");

            if (!Files.exists(pathPubPintor) || !Files.exists(pathPrivPintor)) {
                throw new IllegalStateException("Las llaves EC del pintor no existen en " + dirClavesPintor);
            }
            System.out.println("[TEST PASO 1/6 OK] Llaves EC del pintor verificadas.");

            // 2. Generar llave simétrica AES mediante ECDH (d_pintor * Q_sistema)
            SecretKey claveAES = consola.generarLlaveAESPintor(pintor, pathPrivPintor);
            if (claveAES == null || !claveAES.getAlgorithm().equals("AES")) {
                throw new IllegalStateException("Fallo en la generación de la llave AES compartida.");
            }
            System.out.println("[TEST PASO 2/6 OK] Llave simétrica AES derivada exitosamente.");

            // 3. Crear imagen de prueba en imagenes/ con extensión .bmp (Opción A)
            Path dirImagenes = Paths.get("imagenes");
            Files.createDirectories(dirImagenes);
            Path imagenBmp = dirImagenes.resolve("mona_lisa.bmp");
            byte[] contenidoOriginal = "HEADER_BMP_HEX_PIXELES_DE_MONA_LISA_PINTADA_POR_DAVINCI".getBytes(StandardCharsets.UTF_8);
            Files.write(imagenBmp, contenidoOriginal);

            // 4. Cifrar la imagen con AES-GCM
            byte[] obraCifrada = consola.cifrarImagenPintor(pintor, claveAES, imagenBmp);
            if (obraCifrada == null || obraCifrada.length == 0) {
                throw new IllegalStateException("Fallo en el cifrado de la obra.");
            }

            // Validar Opción A con formato: nombreBase_Cifrado_NombreAutor.<ext>
            Path pathEsperadoCifrado = dirImagenes.resolve("mona_lisa_Cifrado_davinci.bmp");
            if (!Files.exists(pathEsperadoCifrado)) {
                throw new IllegalStateException("El archivo cifrado no se guardó con la extensión original esperada: " + pathEsperadoCifrado);
            }
            System.out.println("[TEST PASO 3/6 OK] Cifrado AES-GCM completado. Archivo generado: " + pathEsperadoCifrado.getFileName() + " (Opción A preservada)");

            // 5. Firmar digitalmente la obra cifrada con la llave privada del pintor
            byte[] firmaDigital = consola.firmarObraCifradaPintor(pintor, obraCifrada, pathEsperadoCifrado);
            if (firmaDigital == null || firmaDigital.length == 0) {
                throw new IllegalStateException("Fallo en la generación de la firma digital ECDSA.");
            }
            System.out.println("[TEST PASO 4/7 OK] Firma digital generada exitosamente. Longitud: " + firmaDigital.length + " bytes.");

            // 5.1 Validar exportación a archivo txt en claves_usuario/pintores/<NombreUsuario>/
            Path pathEsperadoFirma = dirClavesPintor.resolve("firma_" + nombrePintor + ".txt");
            if (!Files.exists(pathEsperadoFirma)) {
                throw new IllegalStateException("El archivo de firma no fue exportado en: " + pathEsperadoFirma);
            }
            byte[] firmaLeidaDeTxt = moduloECDSA.cargarFirmaDigital(pathEsperadoFirma);
            if (!Arrays.equals(firmaDigital, firmaLeidaDeTxt)) {
                throw new IllegalStateException("La firma leída de " + pathEsperadoFirma + " no coincide con la firma generada.");
            }
            System.out.println("[TEST PASO 5/7 OK] Exportación de firma verificada en: " + pathEsperadoFirma);

            // 6. Verificar la firma digital con la llave pública del pintor
            PublicKey pubPintor = moduloECDSA.cargarLlavePublica(pathPubPintor);
            boolean firmaValida = moduloECDSA.verificarFirmaECDSA(obraCifrada, firmaLeidaDeTxt, pubPintor);
            if (!firmaValida) {
                throw new IllegalStateException("La firma digital ECDSA no pudo ser verificada con la llave pública del pintor.");
            }
            System.out.println("[TEST PASO 6/7 OK] Verificación de firma digital leída de txt con llave pública: VÁLIDA.");

            // 7. Prueba de no repudio / detección de fraude: alterar 1 byte de la obra cifrada
            byte[] obraCifradaAlterada = obraCifrada.clone();
            obraCifradaAlterada[obraCifradaAlterada.length - 1] ^= 0x01;
            boolean firmaAlteradaValida = moduloECDSA.verificarFirmaECDSA(obraCifradaAlterada, firmaDigital, pubPintor);
            if (firmaAlteradaValida) {
                throw new IllegalStateException("Error crítico: la firma fue aceptada sobre un contenido alterado.");
            }
            System.out.println("[TEST PASO 7/7 OK] Detección de fraude: La firma digital RECHAZÓ correctamente la obra alterada.");

            // 8. Validar el hash matemático SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashEsperado = md.digest(obraCifrada);
            if (!Arrays.equals(hashEsperado, consola.getUltimoHashObraCifrada())) {
                throw new IllegalStateException("El hash SHA-256 no coincide.");
            }

            System.out.println("\n==============================================================");
            System.out.println(" TODOS LOS TESTS PASARON EXITOSAMENTE (100% OK)");
            System.out.println("==============================================================");
            System.out.println("Hash SHA-256 de obra cifrada (Hex): " + bytesToHex(hashEsperado));
            System.out.println("Firma ECDSA en Base64:              " + Base64.getEncoder().encodeToString(firmaDigital));
            System.out.println("Archivo resultante:                 " + pathEsperadoCifrado);
            System.out.println("==============================================================\n");

        } catch (Exception e) {
            System.err.println("\n[ERROR EN TEST] " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
