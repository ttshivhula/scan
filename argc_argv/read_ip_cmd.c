

#include "parameter.h"

char		**read_ip_cmd(char *parameter)
{
	char	**ip_list;

	ip_list = NULL;
	if (count_params(parameter, ',') > 1)
	{
		printf("here\nN");
		ip_list = split(parameter, ',');
	}
	else
	{
		printf("there\n");
		ip_list = arraypush(ip_list, parameter);
	}
	return (ip_list);
}
