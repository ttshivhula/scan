
#include "scan.h"
#include "parameter.h"

/* print 2d array debug */

void		printarray(char **array)
{
	int		i ;

	i = 0;
	while (array[i])
	{
		printf("array is %s\n", array[i]);
		i++;
	}
}

void		init_nmap_setup(t_nmap_setup *argc_argv)
{
	argc_argv->ip_list = NULL;
	argc_argv->port_list = NULL;
	argc_argv->speedup = 0;
	argc_argv->scan_bitmap = 0;
}

char		**gather_values(t_keyval *key_values, 
	char **(*func)(char *), char *to_find)
{
	t_keyval	*trav;

	trav = key_values;
	while (trav)
	{
		if (strcmp(trav->option, to_find) == 0)
		{
			return ((*func)(trav->param));
		}
		trav = trav->next;
	}
	return (NULL);
}

char		**merge_ip_strings(char **ip_file, char **read_ip_cmd)
{
	if (ip_file == NULL && read_ip_cmd)
		return (read_ip_cmd);
	else if (ip_file && read_ip_cmd == NULL)
		return (ip_file);
	else (arrayjoin(ip_file, read_ip_cmd));
}

t_nmap_setup	resolve_arguments(t_keyval *key_values, int bitmap)
{
	t_nmap_setup	argc_argv;
	char		**(*parser[4])(char *);
	char		**ip_cmd;
	char		**ip_file;

	if (bitmap & HELP)
		usage();
	ip_file = NULL;
	ip_cmd = NULL;
	parser[0] = port_list;
	parser[1] = read_file;
	parser[2] = read_ip_cmd; 	
	init_nmap_setup(&argc_argv);
	if (bitmap & PORTS)
		argc_argv.port_list = gather_values(key_values, parser[0], "ports");
	if (bitmap & IP)
		ip_cmd = gather_values(key_values, parser[2], "ip");
	if (bitmap & MFILE)
		ip_file = gather_values(key_values, parser[1], "file");
	if (bitmap & SPEEDRUN)
	argc_argv.ip_list = merge_ip_string(ip_cmd, ip_file);


	printarray(argc_argv.port_list);
	printarray(ip_cmd);
	printarray(ip_file);
}
