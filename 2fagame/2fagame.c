#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Authentication realm
 */
int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
        if(system("/root/pam-2fa-game-in-archlinux/2fagame/forca") == 34)
        {
           return PAM_SUCCESS;
        }else{
           return PAM_AUTH_ERR;
        }
}

int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv )
{
        
        return PAM_SUCCESS;
}







