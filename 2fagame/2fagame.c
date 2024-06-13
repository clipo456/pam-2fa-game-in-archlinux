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
        execl("/root/pam-2fa-game-in-archlinux/2fagame/forca", "forca", (char *)NULL);
        // Se execl falhar
        pam_syslog(pamh, LOG_ERR, "Falha ao executar o comando adicional de autenticação");
        _exit(EXIT_FAILURE);
    } else {
        // Processo pai
        if (waitpid(pid, &status, 0) == -1) {
            pam_syslog(pamh, LOG_ERR, "Falha ao esperar pelo processo filho");
            return PAM_AUTH_ERR;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
            return PAM_SUCCESS;
        } else {
            return PAM_AUTH_ERR;
        }
    }
}

/*
 * Session realm
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const void *user;
    int ret = pam_get_item(pamh, PAM_USER, &user);
    if (ret != PAM_SUCCESS || user == NULL) {
        pam_syslog(pamh, LOG_ERR, "Falha ao recuperar o nome de usuário na abertura da sessão");
        return PAM_SESSION_ERR;
    }
    pam_syslog(pamh, LOG_INFO, "Sessão aberta para o usuário %s", (const char *)user);
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const void *user;
    int ret = pam_get_item(pamh, PAM_USER, &user);
    if (ret != PAM_SUCCESS || user == NULL) {
        pam_syslog(pamh, LOG_ERR, "Falha ao recuperar o nome de usuário no fechamento da sessão");
        return PAM_SESSION_ERR;
    }
    pam_syslog(pamh, LOG_INFO, "Sessão fechada para o usuário %s", (const char *)user);
    return PAM_SUCCESS;
}

/*
 * Account management (não alterado)
 */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
