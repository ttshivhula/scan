
#ifndef PARAMETER_H
# define PARAMETER_H

# include "alylibc/src/lib.h"
# include "../scan.h"
# include <stdio.h>
# include <string.h>

/*# define PKT_LEN	65536
# define NUL 		0x0
# define SYN 		0x1
# define ACK 		0x2
# define FIN 		0x3
# define UDP 		0x4
# define XMS 		0x5
# define ALL 		0x6
*/


/*
** Nmap setup. All argc/argv variables are resolved at this point
*/

# define HELP		1
# define PORTS		2
# define IP		4
# define MFILE		8
# define SPEEDRUN	16
# define SCAN		32

/*
**  hash table for command line argument handling
*/

typedef struct	s_arg
{
	char		*option;
	char		*param;
	struct s_arg	*next;
}		t_keyval;

t_keyval 	*key_value_pair(t_keyval *keyvalue, 
		char *key, char *val);

/*
** Help screen.
*/

void		usage(void);

/*
** basic cmd error message and exit command.
*/

typedef struct	s_nmap_setup
{
	char		**ip_list;
	char		**port_list;
	size_t		speedup;
	int		scan_bitmap;
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
int             read_scan_type(char *param); // handles --scan
int		read_speedrun(char *thread_count); // handles --speedup
void		usage(void); // handles --help

/*
** Final resolution of all argc/argv parameters
*/ 

t_nmap_setup	resolve_arguments(t_keyval *key_values, int bitmap);

/*
** Wrapper for argc/argv handling bundled into one
*/

t_nmap_setup	init_nmap(int argc, char **argv);


#endif
