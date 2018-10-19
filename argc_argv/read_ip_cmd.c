

#include "parameter.h"

char		**read_ip_cmd(char *parameter)
{
	char	**ip_list;

	ip_list = NULL;
	if (count_args(parameter) > 1)
	{
		ip_list = split(parameter, ',');
	}
	else
	{
		ip_list = arraypush(ip_list, parameter);
	}
	return (ip_list);
}
