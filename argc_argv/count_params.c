
#include "parameter.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

size_t		count_params(char *param_list, char delim)
{
	size_t	list;
	size_t	count;
	bool	comma;

	comma = false;
	count = 1;
	list = 0;
	while (param_list[list])
	{
		if (param_list[list] == delim && comma == false)
		{
			count++;
			comma = true;
		}
		if (param_list[list] != delim && comma == true)
			comma = false;
		list++;
	}
	if (param_list[list - 1] == delim)
		error_and_exit("Error : can't end parameter list with a delim");
	return (count);
}
