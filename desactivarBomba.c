#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define OFFSET_FASE1 0x176e
#define OFFSET_FASE2 0x17c8
#define OFFSET_FASE3 0x182f
#define OFFSET_FASE4 0x18ae
#define OFFSET_FASE5 0x1911
#define OFFSET_FASE6 0x195f

#define FASE_1 1
#define FASE_3 3
#define FASE_5 5

long leer_8_bytes(pid_t pid, unsigned long direccion) {
    return ptrace(PTRACE_PEEKDATA, pid, direccion, 0);
}

void escribir_8_bytes(pid_t pid, unsigned long direccion, long valor) {
    ptrace(PTRACE_POKEDATA, pid, direccion, valor);
}

void escribir_4_bytes(pid_t pid, unsigned long direccion, void *nuevos) {
    long dato = leer_8_bytes(pid, direccion);
    memcpy(&dato, nuevos, 4);
    escribir_8_bytes(pid, direccion, dato);
}

long poner_breakpoint(pid_t pid, unsigned long direccion) {
    long original = leer_8_bytes(pid, direccion);
    unsigned char bytes[8];
    memcpy(bytes, &original, 8);
    bytes[0] = 0xCC;
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
    struct user_regs_struct regs;
    escribir_8_bytes(pid, direccion, original);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    regs.rip = direccion;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
}

void fase_entera(pid_t pid, unsigned long direccion, int fase_actual) {
    struct user_regs_struct regs;
    int clave;
    long original = poner_breakpoint(pid, direccion);
    continuar_y_esperar(pid);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    if (fase_actual == FASE_1){
        clave = regs.r15;
    } else {
        clave = regs.rbx;
    }

    printf("Clave de la fase %d: %d\n", fase_actual, clave);
    escribir_4_bytes(pid, regs.rsp + 0x44, &clave);
    sacar_breakpoint(pid, direccion, original);
}

void fase_float(pid_t pid, int numero, unsigned long direccion, int numero_xmm, int desplazamiento) {
    struct user_fpregs_struct fpregs;
    float clave;
    struct user_regs_struct regs;
    long original = poner_breakpoint(pid, direccion);
    continuar_y_esperar(pid);
    ptrace(PTRACE_GETFPREGS, pid, 0, &fpregs);

    memcpy(&clave, &fpregs.xmm_space[numero_xmm * 4], 4);
    printf("Clave de la fase %d: %f\n", numero, clave);

    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    escribir_4_bytes(pid, regs.rsp + desplazamiento, &clave);
    sacar_breakpoint(pid, direccion, original);
}

void fase_texto(pid_t pid, int numero, unsigned long direccion) {
    struct user_regs_struct regs;
    char clave[16];
    long original = poner_breakpoint(pid, direccion);
    continuar_y_esperar(pid);

    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    long parte1 = leer_8_bytes(pid, regs.rsi);
    long parte2 = leer_8_bytes(pid, regs.rsi + 8);

    memcpy(clave, &parte1, 8);
    memcpy(clave + 8, &parte2, 8);

    printf("Clave de la fase %d: %s\n", numero, clave);

    escribir_8_bytes(pid, regs.rdi, parte1);
    escribir_8_bytes(pid, regs.rdi + 8, parte2);
    sacar_breakpoint(pid, direccion, original);
}

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("./Bomba", "Bomba", NULL);
    }

    waitpid(pid, NULL, 0);

    char ruta[64];
    unsigned long base;
    sprintf(ruta, "/proc/%d/maps", pid);
    FILE *archivo = fopen(ruta, "r");
    fscanf(archivo, "%lx", &base);
    fclose(archivo);

    fase_entera(pid, base + OFFSET_FASE1, FASE_1);
    fase_float(pid, 2, base + OFFSET_FASE2, 3, 0x48);
    fase_entera(pid, base + OFFSET_FASE3, FASE_3);
    fase_texto(pid, 4, base + OFFSET_FASE4);
    fase_entera(pid, base + OFFSET_FASE5, FASE_5);
    fase_float(pid, 6, base + OFFSET_FASE6, 4, 0x4c);

    continuar_y_esperar(pid);
    return 0;
}