
#include "parameter.h"

int		read_speedrun(char *thread_count)
{
	int	count;

	count = atoi(thread_count);
	if (count < 1)
		error_and_exit("Error : '--speedrun'  number invalid\n");
	return (count);
}
