#include <stdio.h>        // printf, fopen, fscanf
#include <stdlib.h>       // exit
#include <string.h>       // memcpy
#include <unistd.h>       // fork, execl
#include <sys/types.h>    // pid_t (número de proceso)
#include <sys/wait.h>     // waitpid
#include <sys/ptrace.h>   // ptrace
#include <sys/user.h>     // struct user_regs_struct y user_fpregs_struct (los registros)

#define OFFSET_FASE1 0x176e   // "cmp DWORD PTR [rsp+0x44], r15d"
#define OFFSET_FASE2 0x17c8   // "ucomiss xmm3, DWORD PTR [rsp+0x48]"
#define OFFSET_FASE3 0x182f   // "cmp DWORD PTR [rsp+0x44], ebx"
#define OFFSET_FASE4 0x18ae   // "call strcmp"   (rdi = mi respuesta, rsi = la clave)
#define OFFSET_FASE5 0x1911   // "cmp DWORD PTR [rsp+0x44], ebx"
#define OFFSET_FASE6 0x195f   // "ucomiss xmm4, DWORD PTR [rsp+0x4c]"


#define REG_R15 0              // para elegir de qué registro leer la clave entera
#define REG_RBX 1


/* ===================== LEER Y ESCRIBIR MEMORIA ===================== */

/* Lee 8 bytes de la memoria de la bomba */
long leer_8_bytes(pid_t pid, unsigned long direccion) {
    return ptrace(PTRACE_PEEKDATA, pid, (void *)direccion, 0);
}

/* Escribe 8 bytes en la memoria de la bomba */
void escribir_8_bytes(pid_t pid, unsigned long direccion, long valor) {
    ptrace(PTRACE_POKEDATA, pid, (void *)direccion, (void *)valor);
}

/* Escribe 4 bytes (un int o un float) sin tocar los 4 bytes de al lado */
void escribir_4_bytes(pid_t pid, unsigned long direccion, unsigned char nuevos[4]) {
    long dato = leer_8_bytes(pid, direccion);
    memcpy(&dato, nuevos, 4);        // piso solo los primeros 4 bytes
    escribir_8_bytes(pid, direccion, dato);
}

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

void continuar_y_esperar(pid_t pid) {
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, NULL, 0);
}

void sacar_breakpoint(pid_t pid, unsigned long direccion, long original) {
    escribir_8_bytes(pid, direccion, original);   // vuelvo a poner los bytes originales
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    regs.rip = direccion;            // el int3 adelantó rip 1 byte: lo vuelvo atrás
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
}


/* ============================ LAS FASES ============================ */

/* Fase con clave ENTERA: la clave está en r15d o en ebx, la respuesta en [rsp+0x44] */
void fase_entera(pid_t pid, int numero, unsigned long direccion, int registro) {
    long original = poner_breakpoint(pid, direccion);
    continuar_y_esperar(pid);                     // la bomba pide la clave y frena en el cmp

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    int clave;
    if (registro == REG_R15) clave = regs.r15;
    else                     clave = regs.rbx;
    printf("Clave de la fase %d: %d\n", numero, clave);

    escribir_4_bytes(pid, regs.rsp + 0x44, (unsigned char *)&clave);
    sacar_breakpoint(pid, direccion, original);
}

/* Fase con clave FLOAT: la clave está en xmm3 o xmm4, la respuesta en [rsp + desplazamiento] */
void fase_float(pid_t pid, int numero, unsigned long direccion, int numero_xmm, int desplazamiento) {
    long original = poner_breakpoint(pid, direccion);
    continuar_y_esperar(pid);                     // la bomba pide la clave y frena en el ucomiss

    struct user_fpregs_struct fpregs;
    ptrace(PTRACE_GETFPREGS, pid, 0, &fpregs);

    float clave;
    memcpy(&clave, &fpregs.xmm_space[numero_xmm * 4], 4);   // cada xmm ocupa 4 posiciones
    printf("Clave de la fase %d: %f\n", numero, clave);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);        // necesito rsp
    escribir_4_bytes(pid, regs.rsp + desplazamiento, (unsigned char *)&clave);
    sacar_breakpoint(pid, direccion, original);
}

/* Fase con clave de TEXTO: frena en el call strcmp; rsi apunta a la clave, rdi a mi respuesta */
void fase_texto(pid_t pid, int numero, unsigned long direccion) {
    long original = poner_breakpoint(pid, direccion);
    continuar_y_esperar(pid);                     // la bomba pide el texto y frena en el call strcmp

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    long parte1 = leer_8_bytes(pid, regs.rsi);        // clave: bytes 0 a 7
    long parte2 = leer_8_bytes(pid, regs.rsi + 8);    // clave: bytes 8 a 15 (incluye el '\0')

    char clave[17];
    memcpy(clave, &parte1, 8);
    memcpy(clave + 8, &parte2, 8);
    clave[16] = '\0';
    printf("Clave de la fase %d: %s\n", numero, clave);

    escribir_8_bytes(pid, regs.rdi, parte1);          // copio la clave sobre mi respuesta
    escribir_8_bytes(pid, regs.rdi + 8, parte2);
    sacar_breakpoint(pid, direccion, original);
}


/* ============================== MAIN ============================== */

int main() {

    /* ===== Crear la bomba como proceso hijo ===== */

    pid_t pid = fork();

    if (pid == 0) {                              // HIJO
        ptrace(PTRACE_TRACEME, 0, 0, 0);         // "quiero que mi padre me controle"
        execl("./Bomba", "Bomba", NULL);         // el hijo se convierte en la bomba
        printf("No se pudo ejecutar ./Bomba\n");
        exit(1);
    }

    waitpid(pid, NULL, 0);                       // PADRE: espero a que la bomba quede frenada


    /* ===== Buscar dónde se cargó la bomba ===== */

    char ruta[64];
    sprintf(ruta, "/proc/%d/maps", pid);
    FILE *archivo = fopen(ruta, "r");
    unsigned long base;
    fscanf(archivo, "%lx", &base);               // el primer número es la base
    fclose(archivo);
    printf("Base de la bomba: 0x%lx\n", base);


    /* ===== Las 6 fases ===== */

    fase_entera(pid, 1, base + OFFSET_FASE1, REG_R15);
    fase_float (pid, 2, base + OFFSET_FASE2, 3, 0x48);    // xmm3, respuesta en [rsp+0x48]
    fase_entera(pid, 3, base + OFFSET_FASE3, REG_RBX);
    fase_texto (pid, 4, base + OFFSET_FASE4);
    fase_entera(pid, 5, base + OFFSET_FASE5, REG_RBX);
    fase_float (pid, 6, base + OFFSET_FASE6, 4, 0x4c);    // xmm4, respuesta en [rsp+0x4c]


    /* ===== Dejar que la bomba termine ===== */

    continuar_y_esperar(pid);
    return 0;
}