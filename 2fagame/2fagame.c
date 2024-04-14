#include <security/pam_modules.h>
#include <stdio.h>

/*
 * Authentication realm
 */

if(system("forca.exe") == 34)
{
    int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv )
    {
        return PAM_SUCCESS;
    }
}
else
{
    int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv )
    {
        PAM_AUTH_ERR;
    }
}



/*
 * Authentication realm
 */


