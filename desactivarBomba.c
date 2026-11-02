#include <stdio.h>
#include <stdlib.h>
 
int main() {
    pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);   /* "quiero que me controlen" */
        execl("./bomba", "bomba", NULL);    /* este proceso pasa a ser la bomba */
    }
    waitpid(pid, NULL, 0);  
}