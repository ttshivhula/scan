
#include "parameter.h"

int             bitmagic(char **flags)
{
        int     bitmap;
        int     i;

        bitmap = 0;
        i = 0;
        while (flags[i])
        {
                if (strcmp(flags[i], "SYN") == 0)
                        bitmap = bitmap |= SYN;
                else if (strcmp(flags[i], "ACK") == 0)
                        bitmap = bitmap |= ACK;
                else if (strcmp(flags[i], "NUL") == 0)
                        bitmap = bitmap |= NUL;
                else if (strcmp(flags[i], "FIN") == 0)
                        bitmap = bitmap |= FIN;
                else if (strcmp(flags[i], "UDP") == 0)
                        bitmap = bitmap |= UDP;
                else if (strcmp(flags[i], "XMS") == 0)
                        bitmap = bitmap |= XMS;
                else if (strcmp(flags[i], "ALL") == 0)
                        bitmap = bitmap |= ALL;
                else
                        error_and_exit("Error : --scan : unknown scan type\n");
                i++;
        }
        return (bitmap);
}

int             read_scan_type(char *param)
{
        char    **scan_list;
        int     bitmap;

        scan_list = NULL;
        if (strchr(param, '|'))
        {
                scan_list = split(param, '|');
        }
        else
        {
                scan_list = arraypush(scan_list, param);
        }
        bitmap = bitmagic(scan_list);
        free2d(scan_list);
        return (bitmap);
}


