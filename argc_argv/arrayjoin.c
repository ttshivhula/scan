
#include "parameter.h"

char		**arrayjoin(char **array1, char **array2)
{
	char	**newarr;
	size_t	i;

	newarr = NULL;
	i = 0;
	while (array1 && array1[i])
	{
		newarr = arraypush(newarr, array1[i]);
		i++;
	}
	i = 0;
	while (array2 && array2[i])
	{
		newarr = arraypush(newarr, array2[i]);
		i++;
	}
	return (newarr);
}
