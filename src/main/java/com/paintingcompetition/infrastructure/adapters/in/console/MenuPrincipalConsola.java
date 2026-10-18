
package com.paintingcompetition.infrastructure.adapters.in.console;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Scanner;
import java.util.UUID;

import com.paintingcompetition.domain.model.RolUsuario;
import com.paintingcompetition.domain.model.Usuario;
import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;
import com.paintingcompetition.domain.ports.out.RegistroECDSAPort;

/**
 * Adaptador de Entrada (Driving Adapter) que implementa
 * una interfaz de usuario por consola.
 *
 * Proporciona un menu de inicio de sesion simulado
 * para interactuar con el sistema criptografico.
 */
public class MenuPrincipalConsola {

    private final Scanner scanner;
    private final MotorCriptograficoPort motorConfidencialidad;
    private final MotorCriptograficoPort motorRegistro;
    private final MotorCriptograficoPort motorAnonimato;

    public MenuPrincipalConsola(
            MotorCriptograficoPort motorConfidencialidad,
            MotorCriptograficoPort motorRegistro,
            MotorCriptograficoPort motorAnonimato) {

        this.scanner = new Scanner(System.in);
        this.motorConfidencialidad = motorConfidencialidad;
        this.motorRegistro = motorRegistro;
        this.motorAnonimato = motorAnonimato;
    }

    // =========================================================
    // MENU PRINCIPAL
    // =========================================================

    public void iniciar() {

        boolean salir = false;

        System.out.println("========================================================");
        System.out.println(" SISTEMA DE CONCURSO DE PINTURA (CORE CRIPTOGRÁFICO)");
        System.out.println(" Arquitectura Hexagonal - Puertos y Adaptadores");
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
                    System.out.println("\nSaliendo del sistema. ¡Hasta pronto!");
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
                RolUsuario.PINTOR
        );

        System.out.println(
                ">> Sesión iniciada con éxito como: "
                + pintor.getNombreUsuario()
                + " (Rol: " + pintor.getRol() + ")"
        );

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
                RolUsuario.JUEZ
        );

        System.out.println(
                ">> Sesión iniciada con éxito como: "
                + juez.getNombreUsuario()
                + " (Rol: " + juez.getRol() + ")"
        );

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
                RolUsuario.ORGANIZADOR
        );

        System.out.println(
                ">> Sesión iniciada con éxito como: "
                + presidente.getNombreUsuario()
                + " (Rol: " + presidente.getRol() + ")"
        );

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
                    + pintor.getNombreUsuario() + ") ---"
            );

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
                            "\n[Simulación]: No hay obras registradas en memoria en este momento."
                    );
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
                "\n[Integración parcial]: Demostración real de autenticidad ECDSA."
        );

        System.out.println(
                "- Módulo AES: "
                + (motorConfidencialidad != null
                ? "Configurado; su cifrado no se ejecuta en esta demostración."
                : "No configurado.")
        );

        System.out.println(
                "- Módulo RSA: "
                + (motorAnonimato != null
                ? "Configurado; su firma ciega no se ejecuta en esta demostración."
                : "No configurado.")
        );

        // Comprobar disponibilidad del puerto ECDSA.
        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {

            System.out.println(
                    "[!] El puerto de autenticidad ECDSA no está configurado."
            );

            return;
        }

        // 1. Solicitar los datos del registro.
        System.out.print(
                "Ingrese el título de la obra para la prueba: "
        );

        String titulo = scanner.nextLine().trim();

        if (titulo.isEmpty()) {

            System.out.println(
                    "[!] Debe indicar el título de la obra."
            );

            return;
        }

        // Crear un registro de prueba unico.
        String registro =
                "PINTOR:" + pintor.getNombreUsuario()
                + "|OBRA:" + titulo
                + "|ID_REGISTRO:" + UUID.randomUUID();

        byte[] datos = registro.getBytes(
                StandardCharsets.UTF_8
        );

        try {

            // 2. Generar par de llaves ECDSA.
            KeyPair llaves =
                    registroECDSA.generarParLlavesECDSA();

            // 3. Firmar con la llave privada.
            byte[] firma = registroECDSA.firmar(
                    datos,
                    llaves.getPrivate()
            );

            // 4. Verificar con la llave publica.
            boolean valida =
                    registroECDSA.verificarFirmaECDSA(
                            datos,
                            firma,
                            llaves.getPublic()
                    );

            // 5. Alterar una copia del registro.
            byte[] datosAlterados = datos.clone();

            datosAlterados[0] ^= 0x01;

            // 6. Verificar el registro modificado.
            boolean validaAlterada =
                    registroECDSA.verificarFirmaECDSA(
                            datosAlterados,
                            firma,
                            llaves.getPublic()
                    );

            // 7. Mostrar resultados.
            System.out.println(
                    "\n--- Resultado de autenticidad ECDSA ---"
            );

            System.out.println(
                    "Curva: secp256r1 | Firma: SHA256withECDSA"
            );

            System.out.println(
                    "Registro original: " + registro
            );

            System.out.println(
                    "Firma digital generada: "
                    + firma.length + " bytes"
            );

            System.out.println(
                    "Verificación del registro original: "
                    + valida
            );

            System.out.println(
                    "Verificación del registro alterado: "
                    + validaAlterada
            );

            if (valida && !validaAlterada) {

                System.out.println(
                        "[OK] Prueba ECDSA completada correctamente."
                );

            } else {

                System.out.println(
                        "[!] La prueba ECDSA no produjo los resultados esperados."
                );
            }

            System.out.println(
                    "[Aviso] Esta prueba no cifra ni guarda la obra o las llaves."
            );

        } catch (RuntimeException e) {

            System.out.println(
                    "[!] No fue posible ejecutar ECDSA: "
                    + e.getMessage()
            );
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
                    + juez.getNombreUsuario() + ") ---"
            );

            System.out.println("1. Validar firma ciega de obra anónima");
            System.out.println("2. Calificar obra");
            System.out.println("3. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    System.out.println(
                            "\n[Simulación]: Verificación con ModuloAnonimatoRSA..."
                    );
                    break;

                case "2":
                    System.out.println(
                            "\n[Simulación]: Asignación de puntaje a obra anónima..."
                    );
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
                    + presidente.getNombreUsuario() + ") ---"
            );

            System.out.println("1. Realizar firma de los votos");
            System.out.println("2. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    System.out.println(
                            "\n[Simulación]: Realizar firma ciega."
                    );
                    break;

                case "2":
                    regresar = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida.");
            }
        }
    }
}
