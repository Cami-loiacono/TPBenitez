#include <stdio.h>        // printf, fopen, fscanf
#include <stdlib.h>       // exit
#include <string.h>       // memcpy
#include <unistd.h>       // fork, execl
#include <sys/types.h>    // pid_t (número de proceso)
#include <sys/wait.h>     // waitpid
#include <sys/ptrace.h>   // ptrace
#include <sys/user.h>     // struct user_regs_struct y user_fpregs_struct (los registros)

#define OFFSET_FASE1 0x176e   // offset del "cmp DWORD PTR [rsp+0x44], r15d"
#define OFFSET_FASE2 0x17c8   // offset del "ucomiss xmm3, DWORD PTR [rsp+0x48]"
#define OFFSET_FASE3 0x182f   // offset del "cmp DWORD PTR [rsp+0x44], ebx"
#define OFFSET_FASE4 0x18ae   // offset del "call strcmp"
#define OFFSET_FASE5 0x1911   // offset del "cmp DWORD PTR [rsp+0x44], ebx"
#define OFFSET_FASE6 0x195f 

/* ======================= FUNCIONES AUXILIARES ======================= */

/* Lee 8 bytes de la memoria de la bomba */
long leer_8_bytes(pid_t pid, unsigned long direccion) {
    return ptrace(PTRACE_PEEKDATA, pid, (void *)direccion, 0);
}

/* Escribe 8 bytes en la memoria de la bomba */
void escribir_8_bytes(pid_t pid, unsigned long direccion, long valor) {
    ptrace(PTRACE_POKEDATA, pid, (void *)direccion, (void *)valor);
}

/* Escribe un int (4 bytes) en la memoria de la bomba, sin tocar los 4 bytes de al lado */
void escribir_int(pid_t pid, unsigned long direccion, int valor) {
    long dato = leer_8_bytes(pid, direccion);
    memcpy(&dato, &valor, 4);        // piso solo los primeros 4 bytes
    escribir_8_bytes(pid, direccion, dato);
}

/* Escribe un float (4 bytes) en la memoria de la bomba, sin tocar los 4 bytes de al lado */
void escribir_float(pid_t pid, unsigned long direccion, float valor) {
    long dato = leer_8_bytes(pid, direccion);
    memcpy(&dato, &valor, 4);        // piso solo los primeros 4 bytes
    escribir_8_bytes(pid, direccion, dato);
}

/* Escribe una cadena de caracteres en la memoria de la bomba */
void escribir_string(pid_t pid, unsigned long direccion, char *valor) {
    long dato = leer_8_bytes(pid, direccion);
    memcpy(&dato, valor, strlen(valor));        // piso solo los primeros strlen(valor) bytes
    escribir_8_bytes(pid, direccion, dato);
}

/* Pone un breakpoint (0xCC) en la dirección. Devuelve los bytes originales */
long poner_breakpoint(pid_t pid, unsigned long direccion) {
    long original = leer_8_bytes(pid, direccion);
    unsigned char bytes[8];
    memcpy(bytes, &original, 8);     // paso los 8 bytes a un arreglo
    bytes[0] = 0xCC;                 // cambio el primero por 0xCC (int3)
    long con_breakpoint;
    memcpy(&con_breakpoint, bytes, 8);
    escribir_8_bytes(pid, direccion, con_breakpoint);
    return original;
}

/* Saca el breakpoint y vuelve rip a la instrucción original */
void sacar_breakpoint(pid_t pid, unsigned long direccion, long original) {
    escribir_8_bytes(pid, direccion, original);   // vuelvo a poner los bytes originales
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    regs.rip = direccion;            // el int3 adelantó rip 1 byte: lo vuelvo atrás
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
}

/* Deja seguir a la bomba y espera a que se frene (o termine) */
void continuar_y_esperar(pid_t pid) {
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, NULL, 0);
}


/* ============================== MAIN ============================== */

int main() {

    /* ===== Crear la bomba como proceso hijo ===== */

    pid_t pid = fork();              // ahora hay 2 copias del programa

    if (pid == 0) {                  // esta parte la ejecuta solo el HIJO
        ptrace(PTRACE_TRACEME, 0, 0, 0);       // "quiero que mi padre me controle"
        execl("./Bomba", "Bomba", NULL);       // el hijo se convierte en la bomba
        printf("No se pudo ejecutar ./Bomba\n");
        exit(1);
    }

    // De acá para abajo lo ejecuta solo el PADRE (nuestro programa)
    waitpid(pid, NULL, 0);           // espero a que la bomba quede frenada al arrancar


    /* ===== Buscar dónde se cargó la bomba ===== */

    char ruta[64];
    sprintf(ruta, "/proc/%d/maps", pid);     // armo el texto "/proc/<pid>/maps"
    FILE *archivo = fopen(ruta, "r");
    unsigned long base;
    fscanf(archivo, "%lx", &base);           // el primer número es la base
    fclose(archivo);

    printf("Base de la bomba: 0x%lx\n", base);

    struct user_regs_struct regs;            // registros comunes (rax, rbx, r15, rsp, rip...)
    struct user_fpregs_struct fpregs;        // registros de punto flotante (xmm0..xmm15)


    /* ============================ FASE 1 ============================ */

    unsigned long dir1 = base + OFFSET_FASE1;
    long original1 = poner_breakpoint(pid, dir1);
    continuar_y_esperar(pid);                // pide la clave (escribí cualquier número) y frena en el cmp
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    int clave1 = regs.r15;                   // la clave está en r15d
    printf("Clave de la fase 1: %d\n", clave1);
    escribir_int(pid, regs.rsp + 0x44, clave1);   // mi respuesta está en [rsp+0x44]
    sacar_breakpoint(pid, dir1, original1);

    /* ============================ FASE 2 ============================ */

    unsigned long dir2 = base + OFFSET_FASE2;
    long original2 = poner_breakpoint(pid, dir2);

    continuar_y_esperar(pid);                // pasa la fase 1, pide la clave de la 2 y frena en el ucomiss
    ptrace(PTRACE_GETFPREGS, pid, 0, &fpregs);
    float clave2;
    memcpy(&clave2, &fpregs.xmm_space[12], 4);    // la clave está en xmm3 = xmm_space[3 * 4]
    printf("Clave de la fase 2: %f\n", clave2);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);        // necesito rsp
    escribir_float(pid, regs.rsp + 0x48, clave2); // mi respuesta está en [rsp+0x48]
    sacar_breakpoint(pid, dir2, original2);


    /* ===== FASE 3 ===== */
    unsigned long dir3 = base + OFFSET_FASE3;
    long original3 = poner_breakpoint(pid, dir3);
    continuar_y_esperar(pid);                // pide la clave de la fase 3 y frena en el cmp
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    int clave3 = regs.r15;                   // la clave está en r15d
    printf("Clave de la fase 3: %d\n", clave3);
    escribir_int(pid, regs.rsp + 0x44, clave3);   // mi respuesta está en [rsp+0x44]
    sacar_breakpoint(pid, dir3, original3);

    /* ===== FASE 4 ===== */
    unsigned long dir4 = base + OFFSET_FASE4;
    long original4 = poner_breakpoint(pid, dir4);
    continuar_y_esperar(pid);                     // pide el texto (escribí cualquier palabra) y frena en el call strcmp
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    // la clave está en la memoria de la bomba, donde apunta rsi: la leo en 2 partes de 8 bytes
    long parte1 = leer_8_bytes(pid, regs.rsi);        // bytes 0 a 7
    long parte2 = leer_8_bytes(pid, regs.rsi + 8);    // bytes 8 a 15 (incluye el '\0')
    // la paso a un arreglo de char de mi programa para poder mostrarla
    char clave4[17];
    memcpy(clave4, &parte1, 8);
    memcpy(clave4 + 8, &parte2, 8);
    clave4[16] = '\0';
    printf("Clave de la fase 4: %s\n", clave4);
    // copio la clave sobre mi respuesta, que está donde apunta rdi
    escribir_8_bytes(pid, regs.rdi, parte1);
    escribir_8_bytes(pid, regs.rdi + 8, parte2);

    sacar_breakpoint(pid, dir4, original4);

    /* ===== FASE 5 ===== */
    unsigned long dir5 = base + OFFSET_FASE5;
    long original5 = poner_breakpoint(pid, dir5);
    continuar_y_esperar(pid);                     // pide la clave de la fase 5 y frena en el cmp
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    int clave5 = regs.rbx;                        // la clave está en ebx
    printf("Clave de la fase 5: %d\n", clave5);
    escribir_int(pid, regs.rsp + 0x44, clave5);   // mi respuesta está en [rsp+0x44]
    sacar_breakpoint(pid, dir5, original5);

    /* ===== FASE 6 ===== */
    unsigned long dir6 = base + OFFSET_FASE6;
    long original6 = poner_breakpoint(pid, dir6);
    continuar_y_esperar(pid);                     // pide la clave de la fase 6 y frena en el ucomiss
    ptrace(PTRACE_GETFPREGS, pid, 0, &fpregs);
    float clave6;
    memcpy(&clave6, &fpregs.xmm_space[16], 4);    // la clave está en xmm4 = xmm_space[4 * 4]
    printf("Clave de la fase 6: %f\n", clave6);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);        // necesito rsp
    escribir_float(pid, regs.rsp + 0x4c, clave6); // mi respuesta está en [rsp+0x4c]
    sacar_breakpoint(pid, dir6, original6);

    /* ===== Dejar que la bomba termine ===== */
    continuar_y_esperar(pid);

    return 0;
}