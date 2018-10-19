

#include "parameter.h"

void		swap_numbers(size_t *start, size_t *end)
{
	size_t	tmp;

	tmp = *start;
	*start = *end;
	*end = tmp;
}

char		**port_range_setup(char *start_to_end)
{
	char	**s_e;
	size_t	start;
	size_t	end;
	char	**list;

	list = 0;
	s_e = split(start_to_end, '-');
	start = atoi(s_e[0]);
	end = atoi(s_e[1]);
	if (start == end)
		error_and_exit("Error : --ports : invalid range");
	if (start > end)
		swap_numbers(&start, &end);
	while (start < end)
	{
		list = arraypush(list, intostr(start));
		start++;	
	}
	return (list);
}

char		**multiple_ports(char *parameter)
{
	char	**listing;
	size_t	i;
	char	**to_return;

	listing = split(parameter, ',');
	i = 0;
	to_return = NULL;
	while (listing[i])
	{
		if (strchr(listing[i], '-'))
			to_return = arraypush(to_return, 
			&(port_range_setup(listing[i]));
		else
			to_return = arraypush(to_return, listing[i]);
		i++;
	}
	return (to_return);
}

char		**single_ports(char *parameter)
{
	char **to_return;
	char *tostr;

	to_return = NULL;
	if (strchr(parameter, '-'))
	{
		to_return = port_range_setup(parameter);
	}
	else
	{
		tostr = intostr(parameter);
		to_return = arraypush(to_return, tostr);
	}
	return (tostr);
}

char		**port_list(char *parameter)
{
	char	*port_list;
	char	**listing;
	size_t	i;

	i = 0;
	listing = NULL;
	if (count_params(parameter) > 1)
	{
		listing = multiple_ports(parameter);
	}
	else
	{
		listing = single_ports(parameter);
	}
}






