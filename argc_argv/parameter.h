
#ifndef PARAMETER_H
# define PARAMETER_H

# include "alylibc/src/lib.h"

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




#endif
