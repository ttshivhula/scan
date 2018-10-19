
#include "scan.h"

void		usage(void)
{
	printf("Help Screen\n");
	printf("ft_nmap [OPTIONS]\n");
	printf(" --help    \tPrint this help screen\n");
	printf(" --ports   \tPorts to scan (eg: 1-10 or 1,2,3 or 1,5-15\n");
	printf(" --ip      \tip addresses to scan in dot format\n");
	printf(" --file    \tFile name containing IP addresses to scan,\n");
	printf(" --speedrun\t[250 max] number of parallele threads to use\n");
	printf(" --scan    \tSYN/NULL/FIN/XMAS/ACK/UDP\n");
	exit(1);
}

unsigned int	bitmap_check(t_keyval *key_value)
{
	t_keyval	*trav;
	unsigned int	field;

	field = 0;
	trav = key_value;
	while (trav)
	{
		if (strcmp(trav->option, "file") == 0)
			field = (field | MFILE);
		else if (strcmp(trav->option, "speedrun") == 0)
			field = (field | SPEEDRUN);
		else if (strcmp(trav->option, "ip") == 0)
			field = (field | IP);
		else if (strcmp(trav->option, "scan") == 0)
			field = (field | SCAN);
		else if (strcmp(trav->option, "ports") == 0)
			field = (field | PORTS);
		else if (strcmp(trav->option, "help") == 0)
			field = (field | HELP);
		trav = trav->next;
	}
	return (field);
}

void		print_keyvalue_pair(t_keyval *keyval)
{
	t_keyval	*trav;

	trav = keyval;
	while (trav)
	{
		printf("K : %s - V : %s\n", trav->option,
			trav->param);
		trav = trav->next;
	}
}

t_keyval	*cmd_options(int argc, char **argv)
{
	int		i;
	t_keyval	*cmd_args;

	cmd_args = NULL;
	i = 1;
	while (i < argc)
	{
		if (strncmp(argv[i], "--", 2) == 0 && 
		i + 1 < argc)
		{
			cmd_args = key_value_pair(cmd_args,
			&argv[i][2], argv[i + 1]);
		}
		else
			usage();
		i += 2;
	}
	return (cmd_args);
}

/*
int	main(int argc, char **argv)
{
	unsigned int field = 0;

	t_keyval *key_value = cmd_options(argc, argv);
	print_keyvalue_pair(key_value);
	field = bitmap_check(key_value);
	if (field & SPEEDRUN)
		printf("speedurn set\n");
	if (field & MFILE)
		printf("mfile set\n");
	if (field & IP)
		printf("ip set\n");
	if (field & HELP)
		printf("help set\n");
}
*e

