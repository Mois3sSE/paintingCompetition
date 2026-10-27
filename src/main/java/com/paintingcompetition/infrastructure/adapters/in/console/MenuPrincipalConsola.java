
package com.paintingcompetition.infrastructure.adapters.in.console;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Scanner;
import java.util.UUID;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.paintingcompetition.domain.model.ActaResultados;
import com.paintingcompetition.domain.model.RolUsuario;
import com.paintingcompetition.domain.model.Usuario;
import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloAnonimatoRSA;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloFirmaRSAPSS;
import com.paintingcompetition.infrastructure.adapters.out.io.GestorArchivosActaAdapter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.nio.file.Path;

import com.paintingcompetition.domain.ports.out.RegistroECDSAPort;

public class MenuPrincipalConsola {

    private final Scanner scanner;
    private final MotorCriptograficoPort motorConfidencialidad;
    private final MotorCriptograficoPort motorRegistro;
    private final MotorCriptograficoPort motorAnonimato;
    private final ModuloFirmaRSAPSS moduloPSS;
    private final GestorArchivosActaAdapter gestorActaIO;

    public MenuPrincipalConsola(
            MotorCriptograficoPort motorConfidencialidad,
            MotorCriptograficoPort motorRegistro,
            MotorCriptograficoPort motorAnonimato) {

        this.scanner = new Scanner(System.in);
        this.motorConfidencialidad = motorConfidencialidad;
        this.motorRegistro = motorRegistro;
        this.motorAnonimato = motorAnonimato;
        this.moduloPSS = new ModuloFirmaRSAPSS();
        this.gestorActaIO = new GestorArchivosActaAdapter(this.moduloPSS);
    }

    public void iniciar() {

        boolean salir = false;

        System.out.println("========================================================");
        System.out.println(" SISTEMA DE CONCURSO DE PINTURA (CORE CRIPTOGRÁFICO)");
        System.out.println("========================================================");

        while (!salir) {

            System.out.println("\n--- Menú Principal: Inicio de Sesión Simulado ---");
            System.out.println("1. Entrar como Pintor");
            System.out.println("2. Entrar como Juez");
            System.out.println("3. Entrar como Presidente");
            System.out.println("4. Salir");
            System.out.print("Seleccione una opción: ");

            String opcion = scanner.nextLine().trim();

            switch (opcion) {

                case "1":
                    loginPintor();
                    break;

                case "2":
                    loginJuez();
                    break;

                case "3":
                    loginPresidente();
                    break;

                case "4":
                    System.out.println("\nSaliendo del sistema. ");
                    salir = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida. Por favor ingrese 1, 2, 3 o 4.");
            }
        }
    }

    // =========================================================
    // INICIO DE SESION POR ACTOR
    // =========================================================

    private void loginPintor() {

        System.out.print("\nIngrese su nombre de Pintor/Autor: ");
        String nombre = scanner.nextLine().trim();

        if (nombre.isEmpty()) {
            nombre = "PintorAnonimo";
        }

        Usuario pintor = new Usuario(
                UUID.randomUUID().toString(),
                nombre,
                RolUsuario.PINTOR);

        System.out.println(
                ">> Sesión iniciada con éxito como: "
                        + pintor.getNombreUsuario()
                        + " (Rol: " + pintor.getRol() + ")");

        menuPintor(pintor);
    }

    private void loginJuez() {

        System.out.print("\nIngrese su nombre de Juez/Calificador: ");
        String nombre = scanner.nextLine().trim();

        if (nombre.isEmpty()) {
            nombre = "JuezOficial";
        }

        Usuario juez = new Usuario(
                UUID.randomUUID().toString(),
                nombre,
                RolUsuario.JUEZ);

        System.out.println(
                ">> Sesión iniciada con éxito como: "
                        + juez.getNombreUsuario()
                        + " (Rol: " + juez.getRol() + ")");

        menuJuez(juez);
    }

    private void loginPresidente() {

        System.out.print("\nIngrese su nombre de Presidente: ");
        String nombre = scanner.nextLine().trim();

        if (nombre.isEmpty()) {
            nombre = "Presidente";
        }

        Usuario presidente = new Usuario(
                UUID.randomUUID().toString(),
                nombre,
                RolUsuario.PRESIDENTE);

        System.out.println(
                ">> Sesión iniciada con éxito como: "
                        + presidente.getNombreUsuario()
                        + " (Rol: " + presidente.getRol() + ")");

        menuPresidente(presidente);
    }

    // =========================================================
    // MENU DEL PINTOR
    // =========================================================

    private void menuPintor(Usuario pintor) {

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Pintor ("
                            + pintor.getNombreUsuario() + ") ---");

            System.out.println("1. Registrar y proteger obra (ECDSA + AES + Blind RSA)");
            System.out.println("2. Consultar mis obras registradas");
            System.out.println("3. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    // NUEVO: Ejecutar prueba real del modulo ECDSA.
                    demostrarRegistroECDSA(pintor);
                    break;

                case "2":
                    System.out.println(
                            "\n[Simulación]: No hay obras registradas en memoria en este momento.");
                    break;

                case "3":
                    regresar = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida.");
            }
        }
    }

    // =========================================================
    // INTEGRANTE 2 - DEMOSTRACION REAL DE ECDSA
    // =========================================================

    /**
     * Demuestra la generacion de llaves, firma digital
     * y verificacion de un registro de obra.
     *
     * Esta demostracion no cifra ni almacena archivos.
     * Los modulos AES y RSA se integraran posteriormente.
     */
    private void demostrarRegistroECDSA(Usuario pintor) {

        System.out.println(
                "\n[Integración parcial]: Demostración real de autenticidad ECDSA.");

        System.out.println(
                "- Módulo AES: "
                        + (motorConfidencialidad != null
                                ? "Configurado; su cifrado no se ejecuta en esta demostración."
                                : "No configurado."));

        System.out.println(
                "- Módulo RSA: "
                        + (motorAnonimato != null
                                ? "Configurado; su firma ciega no se ejecuta en esta demostración."
                                : "No configurado."));

        // Comprobar disponibilidad del puerto ECDSA.
        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {

            System.out.println(
                    "[!] El puerto de autenticidad ECDSA no está configurado.");

            return;
        }

        // 1. Solicitar los datos del registro.
        System.out.print(
                "Ingrese el título de la obra para la prueba: ");

        String titulo = scanner.nextLine().trim();

        if (titulo.isEmpty()) {

            System.out.println(
                    "[!] Debe indicar el título de la obra.");

            return;
        }

        // Crear un registro de prueba unico.
        String registro = "PINTOR:" + pintor.getNombreUsuario()
                + "|OBRA:" + titulo
                + "|ID_REGISTRO:" + UUID.randomUUID();

        byte[] datos = registro.getBytes(
                StandardCharsets.UTF_8);

        try {

            // 2. Generar par de llaves ECDSA.
            KeyPair llaves = registroECDSA.generarParLlavesECDSA();

            // 3. Firmar con la llave privada.
            byte[] firma = registroECDSA.firmar(
                    datos,
                    llaves.getPrivate());

            // 4. Verificar con la llave publica.
            boolean valida = registroECDSA.verificarFirmaECDSA(
                    datos,
                    firma,
                    llaves.getPublic());

            // 5. Alterar una copia del registro.
            byte[] datosAlterados = datos.clone();

            datosAlterados[0] ^= 0x01;

            // 6. Verificar el registro modificado.
            boolean validaAlterada = registroECDSA.verificarFirmaECDSA(
                    datosAlterados,
                    firma,
                    llaves.getPublic());

            // 7. Mostrar resultados.
            System.out.println(
                    "\n--- Resultado de autenticidad ECDSA ---");

            System.out.println(
                    "Curva: secp256r1 | Firma: SHA256withECDSA");

            System.out.println(
                    "Registro original: " + registro);

            System.out.println(
                    "Firma digital generada: "
                            + firma.length + " bytes");

            System.out.println(
                    "Verificación del registro original: "
                            + valida);

            System.out.println(
                    "Verificación del registro alterado: "
                            + validaAlterada);

            if (valida && !validaAlterada) {

                System.out.println(
                        "[OK] Prueba ECDSA completada correctamente.");

            } else {

                System.out.println(
                        "[!] La prueba ECDSA no produjo los resultados esperados.");
            }

            System.out.println(
                    "[Aviso] Esta prueba no cifra ni guarda la obra o las llaves.");

        } catch (RuntimeException e) {

            System.out.println(
                    "[!] No fue posible ejecutar ECDSA: "
                            + e.getMessage());
        }
    }

    // =========================================================
    // MENU DEL JUEZ (SIN MODIFICACIONES FUNCIONALES)
    // =========================================================

    private void menuJuez(Usuario juez) {

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Juez ("
                            + juez.getNombreUsuario() + ") ---");

            System.out.println("1. Validar firma ciega de obra anónima");
            System.out.println("2. Calificar obra");
            System.out.println("3. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    System.out.println(
                            "\n[Simulación]: Verificación con ModuloAnonimatoRSA...");
                    break;

                case "2":
                    System.out.println(
                            "\n[Simulación]: Asignación de puntaje a obra anónima...");
                    break;

                case "3":
                    regresar = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida.");
            }
        }
    }

    // =========================================================
    // MENU DEL PRESIDENTE (SIN MODIFICACIONES FUNCIONALES)
    // =========================================================

    private void menuPresidente(Usuario presidente) {

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Presidente ("
                            + presidente.getNombreUsuario() + ") ---");

            System.out.println("1. Realizar firma ciega de los votos (Simulación RSA)");
            System.out.println("2. Emitir y firmar Acta de Resultados (RSASSA-PSS - FIPS 186-5)");
            System.out.println("3. Verificar firma de un Acta de Resultados existente");
            System.out.println("4. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    System.out.println(
                            "\n[Simulación]: Realizar firma ciega.");
                    simulacionPresidente();
                    break;

                case "2":
                    emitirYFirmarActaResultados(presidente);
                    break;

                case "3":
                    verificarFirmaActaExistente();
                    break;

                case "4":
                    regresar = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida.");
            }
        }
    }

    private void emitirYFirmarActaResultados(Usuario presidente) {
        System.out.println("\n==============================================================");
        System.out.println(" EMISIÓN Y FIRMA DE ACTA DE RESULTADOS (RSASSA-PSS - FIPS 186-5)");
        System.out.println("==============================================================");

        try {
            // 1. Gestión de Llaves: Cargar existentes o generar nuevas
            PublicKey pubKey = null;
            PrivateKey privKey = null;

            System.out.println("1. Cargar llaves existentes desde archivos de texto (.txt)");
            System.out.println("2. Generar un nuevo par de llaves (3072 bits - Bouncy Castle)");
            System.out.print("Seleccione una opción (1 o 2, ENTER para 1 si existen): ");
            String opcionLlave = scanner.nextLine().trim();

            if ("1".equals(opcionLlave) || opcionLlave.isEmpty()) {
                System.out.print(
                        "Ingrese la ruta de la LLAVE PRIVADA : ");
                String rutaPriv = scanner.nextLine().trim();
                if (rutaPriv.isEmpty()) {
                    if (Files.exists(Paths.get("priv_presidente.txt"))) {
                        rutaPriv = "priv_presidente.txt";
                    } else {
                        rutaPriv = "clave_privada_presidente.txt";
                    }
                }

                System.out.print(
                        "Ingrese la ruta de la LLAVE PÚBLICA : ");
                String rutaPub = scanner.nextLine().trim();
                if (rutaPub.isEmpty()) {
                    if (Files.exists(Paths.get("pub_presidente.txt"))) {
                        rutaPub = "pub_presidente.txt";
                    } else {
                        rutaPub = "clave_publica_presidente.txt";
                    }
                }

                if (Files.exists(Paths.get(rutaPriv)) && Files.exists(Paths.get(rutaPub))) {
                    try {
                        privKey = gestorActaIO.cargarLlavePrivadaBase64(rutaPriv);
                        pubKey = gestorActaIO.cargarLlavePublicaBase64(rutaPub);
                        System.out.println(" Llave privada cargada de: " + rutaPriv);
                        System.out.println("  Llave pública cargada de: " + rutaPub);
                    } catch (Exception ex) {
                        System.out.println("  [!] Error al cargar las llaves: " + ex.getMessage());
                    }
                } else {
                    System.out.println("  [!] No se encontraron los archivos especificados.");
                }
            }

            // Si no se cargaron llaves existentes, generar un par nuevo
            if (privKey == null || pubKey == null) {
                System.out.println("\nGenerando nuevo par de llaves RSA-PSS de 3072 bits con Bouncy Castle...");
                KeyPair parLlaves = moduloPSS.generarParLlaves();
                pubKey = parLlaves.getPublic();
                privKey = parLlaves.getPrivate();

                RSAPublicKey rsaPub = (RSAPublicKey) pubKey;
                System.out.println(
                        "  Algoritmo: " + rsaPub.getAlgorithm() + " (" + rsaPub.getModulus().bitLength() + " bits)");
                System.out.println("  Exponente Público e: " + rsaPub.getPublicExponent());

                System.out.println("\nExportación de llaves en Base64 a archivos de texto:");
                System.out.print("Ingrese el nombre/ruta para la LLAVE PÚBLICA : ");
                String rutaPub = scanner.nextLine().trim();
                if (rutaPub.isEmpty()) {
                    rutaPub = "pub_presidente.txt";
                }

                System.out.print("Ingrese el nombre/ruta para la LLAVE PRIVADA : ");
                String rutaPriv = scanner.nextLine().trim();
                if (rutaPriv.isEmpty()) {
                    rutaPriv = "priv_presidente.txt";
                }

                gestorActaIO.guardarParLlavesBase64(parLlaves, rutaPub, rutaPriv);
                System.out.println("  Llave pública exportada exitosamente a: " + rutaPub);
                System.out.println("  Llave privada exportada exitosamente a: " + rutaPriv);
            }

            // 2. Documento del Acta de Resultados en texto plano
            System.out.println("\nDocumento del Acta de Resultados:");
            System.out.print(
                    "Ingrese la ruta del archivo de texto del acta : ");
            String rutaActa = scanner.nextLine().trim();
            if (rutaActa.isEmpty()) {
                rutaActa = "acta_resultados_oficial.txt";
            }

            if (!Files.exists(Paths.get(rutaActa))) {
                String plantillaActa = "====================================================\n"
                        + " ACTA OFICIAL DE RESULTADOS - CONCURSO DE PINTURA 2026\n"
                        + " EMISOR: Presidente (" + presidente.getNombreUsuario() + ")\n"
                        + "====================================================\n"
                        + "1er Lugar: 'Amanecer en el Valle' - Promedio: 3★\n"
                        + "2do Lugar: 'Sombras de Otoño'     - Promedio: 2★\n"
                        + "3er Lugar: 'Horizonte Azul'      - Promedio: 1★\n\n"
                        + "Certificación oficial: Se declaran los resultados válidos, inalterables\n"
                        + "y respaldados bajo el esquema de firma digital FIPS 186-5.\n"
                        + "====================================================\n";
                Files.writeString(Paths.get(rutaActa), plantillaActa, StandardCharsets.UTF_8);
                System.out.println("  Archivo de texto plano generado: " + rutaActa);
            } else {
                System.out.println("  Archivo de acta detectado y cargado: " + rutaActa);
            }

            String rutaFirma = "firma_acta_presidente.txt";
            String firmaAnteriorBase64 = null;
            if (Files.exists(Paths.get(rutaFirma))) {
                try {
                    firmaAnteriorBase64 = Files.readString(Paths.get(rutaFirma), StandardCharsets.UTF_8).trim();
                } catch (Exception ignored) {
                }
            }

            System.out.println("\n Firmando documento con ModuloFirmaRSAPSS (usando la clave privada)...");
            String nuevaFirmaBase64 = gestorActaIO.firmarActaYRetornarBase64(rutaActa, privKey);

            Files.writeString(Paths.get(rutaFirma), nuevaFirmaBase64, StandardCharsets.UTF_8);

            System.out.println("\n==============================================================");
            System.out.println(" SALIDA CRIPTOGRÁFICA - FIRMA DIGITAL RSASSA-PSS (FIPS 186-5)");
            System.out.println("==============================================================");
            System.out.println("Documento firmado: " + rutaActa);
            System.out.println("Emisor oficial: PRESIDENTE (" + presidente.getNombreUsuario() + ")");
            System.out.println("Algoritmo de firma: " + ModuloFirmaRSAPSS.ALGORITMO_FIRMA);
            System.out.println("Proveedor: " + ModuloFirmaRSAPSS.PROVEEDOR_BC + " (Bouncy Castle)");
            System.out.println("Función Hash: " + ModuloFirmaRSAPSS.HASH_ALGORITMO);
            System.out.println("Función MGF: " + ModuloFirmaRSAPSS.MGF_ALGORITMO + " con SHA-256");
            System.out.println("Longitud de Salt (sLen): " + ModuloFirmaRSAPSS.LONGITUD_SALT_BYTES + " bytes");
            System.out.println("Archivo de firma guardado en: " + rutaFirma);
            System.out.println("\nFirma Digital Generada (Base64):\n" + nuevaFirmaBase64);
            System.out.println("==============================================================");

            if (firmaAnteriorBase64 != null && opcionLlave.equals("1")) {
                System.out.println("\n--- Comparacion entre firmas  ---");
                System.out.println("Firma anterior (primeros 60 caracteres):  "
                        + firmaAnteriorBase64.substring(0, Math.min(60, firmaAnteriorBase64.length())) + "...");
                System.out.println("Nueva firma generada (primeros 60 chars): "
                        + nuevaFirmaBase64.substring(0, Math.min(60, nuevaFirmaBase64.length())) + "...");
            }

            boolean esValida = gestorActaIO.verificarFirmaActa(rutaActa, nuevaFirmaBase64, pubKey);
            System.out.println("\n Verificación de la firma generada: "
                    + (esValida ? "VÁLIDA " : "INVÁLIDA "));

            System.out.print("\n¿Desea probar la detección de fraude simulando una alteración al acta? (s/n): ");
            String probar = scanner.nextLine().trim();
            if (probar.equalsIgnoreCase("s")) {
                byte[] contenidoOriginal = Files.readAllBytes(Paths.get(rutaActa));
                byte[] contenidoAlterado = contenidoOriginal.clone();
                contenidoAlterado[contenidoAlterado.length - 1] ^= 0x01;
                Path pathAlterado = Paths.get("acta_temporal_alterada.txt");
                Files.write(pathAlterado, contenidoAlterado);

                boolean verificacionAlterada = gestorActaIO.verificarFirmaActa(
                        pathAlterado.toString(), nuevaFirmaBase64, pubKey);
                Files.deleteIfExists(pathAlterado);

                System.out.println("Resultado de verificación con documento alterado: " + verificacionAlterada);
                if (!verificacionAlterada) {
                    System.out
                            .println("RSASSA-PSS detectó la modificación y rechazó la firma.");
                }
            }

        } catch (Exception e) {
            System.out.println("[!] Ocurrió un error al emitir el acta: " + e.getMessage());
        }
    }

    /**
     * Permite verificar la firma digital de un Acta de Resultados existente
     * utilizando su documento en texto plano, archivo de firma y llave pública.
     */
    private void verificarFirmaActaExistente() {
        System.out.println("\n==============================================================");
        System.out.println(" VERIFICACIÓN DE FIRMA DIGITAL DE ACTA (RSASSA-PSS)");
        System.out.println("==============================================================");

        try {
            System.out
                    .print("Ingrese ruta del documento de texto del acta (ENTER para 'acta_resultados_oficial.txt'): ");
            String rutaActa = scanner.nextLine().trim();
            if (rutaActa.isEmpty()) {
                rutaActa = "acta_resultados_oficial.txt";
            }

            System.out.print(
                    "Ingrese ruta del archivo con la firma en Base64 (ENTER para 'firma_acta_presidente.txt'): ");
            String rutaFirma = scanner.nextLine().trim();
            if (rutaFirma.isEmpty()) {
                rutaFirma = "firma_acta_presidente.txt";
            }

            System.out.print(
                    "Ingrese ruta del archivo de la llave pública (ENTER para 'clave_publica_presidente.txt'): ");
            String rutaPub = scanner.nextLine().trim();
            if (rutaPub.isEmpty()) {
                rutaPub = "clave_publica_presidente.txt";
            }

            if (!Files.exists(Paths.get(rutaActa))) {
                System.out.println("[!] El archivo del acta no existe: " + rutaActa);
                return;
            }
            if (!Files.exists(Paths.get(rutaFirma))) {
                System.out.println("[!] El archivo de firma no existe: " + rutaFirma);
                return;
            }
            if (!Files.exists(Paths.get(rutaPub))) {
                System.out.println("[!] El archivo de clave pública no existe: " + rutaPub);
                return;
            }

            PublicKey pubKey = gestorActaIO.cargarLlavePublicaBase64(rutaPub);
            String firmaBase64 = Files.readString(Paths.get(rutaFirma), StandardCharsets.UTF_8).trim();

            boolean valida = gestorActaIO.verificarFirmaActa(rutaActa, firmaBase64, pubKey);

            System.out.println("\n--- RESULTADO DE LA VERIFICACIÓN ---");
            System.out.println("Documento: " + rutaActa);
            System.out.println("Clave pública: " + rutaPub);
            if (valida) {
                System.out.println(">> ESTADO: [FIRMA DIGITAL VÁLIDA] ✓");
                System.out.println(
                        "El documento es auténtico, fue firmado por el Presidente y no ha sufrido alteraciones.");
            } else {
                System.out.println(">> ESTADO: [!] FIRMA INVÁLIDA O DOCUMENTO MODIFICADO ✗");
            }

        } catch (Exception e) {
            System.out.println("[!] Error en la verificación: " + e.getMessage());
        }
    }

    private void simulacionPresidente() {
        try {
            System.out.println("========== INICIANDO LA SIMULACION ==========");
            ModuloAnonimatoRSA modulo = new ModuloAnonimatoRSA();

            System.out.println("(SISTEMA) Generacion de llaves TSA con 3072 para presidente");
            KeyPair llavesPresidente = modulo.generarParLlavesRSA();
            RSAPublicKey llavePublica = (RSAPublicKey) llavesPresidente.getPublic();
            RSAPrivateKey llavePrivada = (RSAPrivateKey) llavesPresidente.getPrivate();

            int[] votosDejueces = { 2, 1, 3 };
            String[] comentariosDejueces = { "Fue un buen trabajo pero le falta trabajar mas las sombras",
                    "Le falta mucha tecnica por conocer", "De los mejores trabajos que he visto"
            };
            byte[][] votoByte = new byte[3][];

            for (int i = 0; i < votosDejueces.length; i++) {
                int numerojuez = i + 1;
                int voto = votosDejueces[i];
                String comentario = comentariosDejueces[i];
                String paqueteVoto = "ESTRELLAS:" + voto + "|COMENTARIO:" + comentario;
                votoByte[i] = paqueteVoto.getBytes(StandardCharsets.UTF_8);

                BigInteger factorCegado = modulo.generarFactorCegado(llavePublica);
                byte[] votoCegado = modulo.cegarMensaje(votoByte[i], factorCegado, llavePublica);
                byte[] firmaCegada = modulo.firmarCegadoRSA(votoCegado, llavePrivada);

                byte[] firmaReal = modulo.descegarFirmaRSA(firmaCegada, factorCegado, llavePublica);
                System.out.println("(SISTEMA) Exportando el archivo ");
                String rutaArchivo = "firma_voto_juez_" + numerojuez + ".txt";
                String firmaBase64 = Base64.getEncoder().encodeToString(firmaReal);
                Files.writeString(Paths.get(rutaArchivo), firmaBase64);

            }

            System.out.println("===== Verificacion de archivos ===== ");
            this.scanner.nextLine();
            for (int i = 0; i < votosDejueces.length; i++) {
                int numerojuez = i + 1;
                String rutaArchivo = "firma_voto_juez_" + numerojuez + ".txt";
                try {
                    String firmaLeidaBase64 = Files.readString(Paths.get(rutaArchivo));
                    byte[] firmaParaVerificar = Base64.getDecoder().decode(firmaLeidaBase64);
                    boolean esValido = modulo.verificarFirmaRSA(votoByte[i], firmaParaVerificar, llavePublica);
                    if (esValido)
                        System.out.println("Firma del juez " + numerojuez + " valida");
                    else
                        System.out.println("Firma del juez " + numerojuez + "  NO valida");
                } catch (Exception e) {
                    System.out.println("Firma ilegible");
                }
            }

        } catch (Exception e) {
            System.out.println("Ocurrio un error en la simulacion ");
        }
    }
}
