
#include "parameter.h"

void		init_nmap_setup(t_nmap_setup *argc_argv)
{
	argc_argv->ip_list = NULL;
	argc_argv->port_list = NULL;
	argc_argv->speedup = 0;
	argc_argv->scan_bitmap = 0;
}

char		**gather_ports(t_keyval *key_values)
{
	t_keyval	*trav;

	trav = key_values;
	while (trav)
	{
		if (strcmp(trav->option, "ports") == 0)
		{
			return (port_list(trav->params));
		}
		trav = trav->next;
	}
	return (NULL);
}

t_nmap_setup	resolve_arguments(t_keyval *key_values, int bitmap)
{
	t_nmap_setup	argc_argv;

	init_nmap_setup(&argc_argv);
	if (bitmap & PORTS)
		argc_argv.port_list = gather_ports(key_values);
}
