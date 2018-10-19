
#ifndef PARAMETER_H
# define PARAMETER_H

# include "scan.h"
# include "alylibc/src/lib.h"

/*
** Nmap setup. All argc/argv variables are resolved at this point
*/

typedef struct	s_nmap_setup
{
	char	**ip_list;
	char	**port_list;
	size_t	speedup;
	int	scan_bitmap;
}		t_nmap_setup;

/*
** to count parameters separated by the delim in the *params string
*/

size_t		count_params(char *params, char delim);

/*
** error and exit function
*/

void		error_and_exit(char *msg);

/*
** Turns a number into a string (for --port flag) 
*/

char		*intostr(size_t size);

/*
** Merges 2 arrays into 1
*/

char		**arrayjoin(char **array1, char **array2);

/*
** All argc/argv read functions
*/

char		**read_file(char *param);  // handles --file
char		**port_list(char *parameter); // handles --ports
char		**read_ip_cmd(char *parameter); // handles --ip
int		read_speedrun(char *thread_count); // handles --speedup
void		usage(void); // handles --help

/*
** Final resolution of all argc/argv parameters
*/ 

t_nmap_setup	resolve_arguments(t_keyval *key_values, int bitmap);





#endif
