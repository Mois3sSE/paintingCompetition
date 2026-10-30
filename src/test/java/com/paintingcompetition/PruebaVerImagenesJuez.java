package com.paintingcompetition;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import com.paintingcompetition.domain.model.RolUsuario;
import com.paintingcompetition.domain.model.Usuario;
import com.paintingcompetition.infrastructure.adapters.in.console.MenuPrincipalConsola;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloAnonimatoRSA;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloConfidencialidadAES;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloRegistroECDSA;

/**
 * Prueba de la funcionalidad de listado de imágenes y verificación de firma
 * para el Juez:
 * 1. Filtra y remueve el texto "_cifrada".
 * 2. Elimina duplicados si existen tanto la normal como la cifrada.
 * 3. Selección y verificación de autenticidad de la obra con la llave pública
 * del pintor.
 * 4. Valida que imprima "VALIDA" para firmas intactas e "INVALIDA" para firmas
 * alteradas.
 */
public class PruebaVerImagenesJuez {

    public static void main(String[] args) {
        System.out.println("==============================================================");
        System.out.println(" INICIANDO TEST: VER IMÁGENES Y VERIFICACIÓN ECDSA (JUEZ)");
        System.out.println("==============================================================");

        try {
            ModuloConfidencialidadAES moduloAES = new ModuloConfidencialidadAES();
            ModuloRegistroECDSA moduloECDSA = new ModuloRegistroECDSA();
            ModuloAnonimatoRSA moduloRSA = new ModuloAnonimatoRSA();
            MenuPrincipalConsola consola = new MenuPrincipalConsola(moduloAES, moduloECDSA, moduloRSA);

            // Asegurar que existan archivos cifrados de prueba para el catálogo
            Path dirImagenes = Paths.get("imagenes");
            Files.createDirectories(dirImagenes);
            Path pathBanderaCifrada = dirImagenes.resolve("bandera_Cifrado_moi.bmp");
            if (!Files.exists(pathBanderaCifrada)) {
                Files.writeString(pathBanderaCifrada, "PAYLOAD_CIFRADO_BANDERA_MOI");
            }
            Path pathMonaCifrada = dirImagenes.resolve("mona_lisa_Cifrado_davinci.bmp");
            if (!Files.exists(pathMonaCifrada)) {
                PruebaFirmaObraCifradaECDSA.main(new String[0]);
            }

            // 1. Obtener catálogo de obras con autor en imagenes/
            List<MenuPrincipalConsola.InfoObraJuez> catalogo = consola.obtenerCatalogoObrasJuez();
            System.out.println("[TEST PASO 1/5 OK] Catálogo detectado: " + catalogo);

            // Validar que se identifiquen autores
            boolean tieneAutorMoi = catalogo.stream().anyMatch(
                    o -> o.getNombreObra().equalsIgnoreCase("bandera.bmp") && o.getAutor().equalsIgnoreCase("moi"));
            boolean tieneAutorDavinci = catalogo.stream()
                    .anyMatch(o -> o.getNombreObra().equalsIgnoreCase("mona_lisa.bmp")
                            && o.getAutor().equalsIgnoreCase("davinci"));
            if (!tieneAutorMoi || !tieneAutorDavinci) {
                throw new IllegalStateException(
                        "El catálogo debe asociar bandera.bmp con 'moi' y mona_lisa.bmp con 'davinci'.");
            }
            System.out.println("[TEST PASO 2/5 OK] Autores 'moi' y 'davinci' identificados automáticamente.");

            // 2. Verificar la firma de la obra "mona_lisa.bmp" para el pintor detectado
            // "davinci"
            System.out.println("\n--- Probando verificación con firma auténtica e intacta ---");
            boolean validaOriginal = consola.verificarFirmaObraPintor("mona_lisa.bmp", "davinci");
            if (!validaOriginal) {
                throw new IllegalStateException("Se esperaba que la firma de mona_lisa.bmp para davinci fuera VALIDA.");
            }
            System.out.println("[TEST PASO 3/5 OK] Verificación de firma auténtica mona_lisa.bmp: VALIDA comprobado.");

            // 3. Validar recuperación de la llave AES por el sistema mediante d_sistema *
            // Q_pintor
            javax.crypto.SecretKey claveAESRecuperada = consola.getUltimaClaveAESRecuperada();
            if (claveAESRecuperada == null) {
                throw new IllegalStateException("El sistema debía recuperar la llave AES tras la firma válida.");
            }
            Usuario pintorDavinci = new Usuario("user-davinci-id", "davinci", RolUsuario.PINTOR);
            javax.crypto.SecretKey claveAESPintor = consola.generarLlaveAESPintor(pintorDavinci,
                    Paths.get("claves_usuario", "pintores", "davinci", "priv_davinci.txt"));
            if (!java.util.Arrays.equals(claveAESRecuperada.getEncoded(), claveAESPintor.getEncoded())) {
                throw new IllegalStateException(
                        "La llave AES recuperada por el sistema no coincide con la generada por el pintor.");
            }
            System.out.println(
                    "[TEST PASO 4/6 OK] Llave AES recuperada por el sistema (d_sistema * Q_davinci) coincide al 100% con la del pintor.");

            // 4. Validar que la imagen descifrada existe en "imagenes/" con formato
            // "nombreBase_descifrada_nombreUsuario.<ext>"
            Path pathDescifradoEsperado = Paths.get("imagenes", "mona_lisa_descifrada_davinci.bmp");
            if (!Files.exists(pathDescifradoEsperado)) {
                throw new IllegalStateException("La imagen descifrada no fue generada en: " + pathDescifradoEsperado);
            }
            byte[] bytesDescifrados = Files.readAllBytes(pathDescifradoEsperado);
            byte[] bytesOriginalesPlano = Files.readAllBytes(Paths.get("imagenes", "mona_lisa.bmp"));
            if (!java.util.Arrays.equals(bytesDescifrados, bytesOriginalesPlano)) {
                throw new IllegalStateException("El contenido de la imagen descifrada no coincide con el original.");
            }
            System.out
                    .println("[TEST PASO 5/6 OK] Imagen descifrada generada y verificada byte a byte con la original: "
                            + pathDescifradoEsperado);

            // 5. Simular alteración a la obra cifrada para probar detección de fraude
            System.out.println("\n--- Probando verificación con obra cifrada alterada ---");
            Files.deleteIfExists(pathDescifradoEsperado); // Eliminar para comprobar que NO se descifra si es inválida
            Path pathObraCifrada = Paths.get("imagenes", "mona_lisa_Cifrado_davinci.bmp");
            byte[] bytesOriginales = Files.readAllBytes(pathObraCifrada);

            byte[] bytesAlterados = bytesOriginales.clone();
            bytesAlterados[bytesAlterados.length - 1] ^= 0x01; // Alterar 1 bit
            Files.write(pathObraCifrada, bytesAlterados);

            boolean validaAlterada = consola.verificarFirmaObraPintor("mona_lisa.bmp", "davinci");
            if (validaAlterada) {
                // Restaurar de inmediato
                Files.write(pathObraCifrada, bytesOriginales);
                throw new IllegalStateException("Se esperaba que la firma alterada fuera INVALIDA.");
            }
            if (Files.exists(pathDescifradoEsperado)) {
                Files.write(pathObraCifrada, bytesOriginales);
                throw new IllegalStateException("No se debió descifrar ninguna imagen cuando la firma es INVALIDA.");
            }
            // Restaurar archivo original
            Files.write(pathObraCifrada, bytesOriginales);
            System.out.println("[TEST PASO 6/6 OK] Detección de alteración: INVALIDA y NO se descifró nada.");

            System.out.println("==============================================================");
            System.out.println(" [OK] TODOS LOS CASOS DE PRUEBA DEL JUEZ PASARON EXITOSAMENTE");
            System.out.println("==============================================================\n");

        } catch (Exception e) {
            System.err.println("\n[!] ERROR EN TEST: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
