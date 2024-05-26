#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/*
 * Authentication realm
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret;
    int status;
    pid_t pid;

    // Check if the primary authentication has already succeeded
    const void *user;
    ret = pam_get_item(pamh, PAM_USER, &user);
    if (ret != PAM_SUCCESS || user == NULL) {
        pam_syslog(pamh, SIG_ERR, "Failed to retrieve username or primary auth failed");
        return PAM_AUTH_ERR;
    }

    pid = fork();
    if (pid == -1) {
        // Fork failed
        pam_syslog(pamh, SIG_ERR, "Fork failed");
        return PAM_AUTH_ERR;
    } else if (pid == 0) {
        // Child process
        execl("/root/pam-2fa-game-in-archlinux/2fagame/forca", "forca", NULL);
        // If execl returns, it must have failed
        _exit(EXIT_FAILURE);
    } else {
        // Parent process
        if (waitpid(pid, &status, 0) == -1) {
            pam_syslog(pamh, SIG_ERR, "Waitpid failed");
            return PAM_AUTH_ERR;
        }
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 34) {
            return PAM_SUCCESS;
        } else {
            return PAM_AUTH_ERR;
        }
    }
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Typically, setcred is used to establish credentials after authentication
    return PAM_SUCCESS;
}
