#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h> 

/*
 * Authentication realm
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret;
    int status;
    pid_t pid;

    // Verifique se a autenticação primária foi bem-sucedida
    const void *user;
    ret = pam_get_item(pamh, PAM_USER, &user);
    if (ret != PAM_SUCCESS || user == NULL) {
        pam_syslog(pamh, LOG_ERR, "Falha ao recuperar o nome de usuário ou autenticação primária falhou");
        return PAM_AUTH_ERR;
    }

    // Autenticação adicional
    pid = fork();
    if (pid == -1) {
        // Falha ao criar um novo processo
        pam_syslog(pamh, LOG_ERR, "Falha ao criar um novo processo");
        return PAM_AUTH_ERR;
    } else if (pid == 0) {
        // Processo filho
        execl("/root/pam-2fa-game-in-archlinux/2fagame/forca", "forca", NULL);
        // Se execl retornar, deve ter falhado
        _exit(EXIT_FAILURE);
    } else {
        // Processo pai
        if (waitpid(pid, &status, 0) == -1) {
            pam_syslog(pamh, LOG_ERR, "Falha ao esperar o processo filho");
            return PAM_AUTH_ERR;
        }

        // Verifique o status de saída do processo filho
        if (WIFEXITED(status)) {
            int exit_status = WEXITSTATUS(status);
            if (exit_status == 34) {
                pam_syslog(pamh, LOG_INFO, "Autenticação adicional bem-sucedida com código de saída: %d", exit_status);
                return PAM_SUCCESS;
            } else {
                pam_syslog(pamh, LOG_ERR, "Autenticação adicional falhou com código de saída: %d", exit_status);
                return PAM_AUTH_ERR;
            }
        } else {
            pam_syslog(pamh, LOG_ERR, "Processo filho terminou de forma anormal");
            return PAM_AUTH_ERR;
        }
    }
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Geralmente, setcred é usado para estabelecer credenciais após a autenticação
    return PAM_SUCCESS;
}
