#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>      /* fork, execl */
#include <sys/types.h>   /* pid_t */
#include <sys/wait.h>    /* waitpid */
#include <sys/ptrace.h>  /* ptrace */

int main() {
    pid_t pid;

    pid = fork();
    if (pid == 0) { //solo entra si es el hijo. Si es el padre, pid es el PID del hijo y es > 0
        ptrace(PTRACE_TRACEME, 0, 0, 0);          /* "quiero que me controlen" */
        execl("./bomba", "bomba", (char *)NULL);  /* este proceso pasa a ser la bomba */
        perror("execl");                          /* solo llega acá si execl falló */
        exit(1);
    }

    /* PADRE */
    waitpid(pid, NULL, 0);   /* la bomba queda frenada justo después del execl */

    /* PASO 2: buscar la dirección base de la bomba */
    char ruta[64];
    unsigned long base; //PARA EL NOMBRE DEL ARCHIVO
    sprintf(ruta, "/proc/%d/maps", pid); // Acá se va a guardar la dirección de memoria donde se cargó la bomba
    FILE *f = fopen(ruta, "r");
    fscanf(f, "%lx", &base);   /* la primera línea empieza con la base */
    fclose(f);
    printf("Base de la bomba: 0x%lx\n", base);

    /* por ahora la dejamos terminar */
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, NULL, 0);
    return 0;
}