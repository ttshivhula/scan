
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "parameter.h"

int		whitespace_newline(char c)
{
	return (c == '\t' || c == '\n' || c == ' ');
}

char		*normalize_str(char *string)
{
	size_t	i;
	char	*newstring;
	size_t	j;

	newstring = (char*)malloc(sizeof(char) * strlen(string) + 1);
	i = 0;
	j = 0;
	while (string[i])
	{
		if (whitespace_newline(string[i]))
		{
			newstring[j++] = ' ';
			while (whitespace_newline(string[i]))
				i++;
		}
		else
		{	
			newstring[j] = string[i];
			i++;
			j++;
		}
	}
	newstring[j] = '\0';
	free(string);
	return (newstring);
}

char		*read_ip_file(char *filename)
{
	int	fd;
	char	*file_content;
	char	buffer[4096];
	char	*tmp;

	if ((fd = open(filename, O_RDONLY)) < 0)
		error_and_exit("Error '--file' think before you do dumb shit");
	file_content = (char*)malloc(sizeof(char));
	bzero(file_content, sizeof(char));
	bzero(buffer, 4096);
	while ((read(fd, buffer, 4096)))
	{
		tmp = join(file_content, buffer);
		free(file_content);
		file_content = strdup(tmp);
		free(tmp);
		bzero(buffer, 4096);
	}
	return (file_content);
}

/*
** Incase a list of files are passd as parameters for the --file flag
** this will open each file, read it's contents and concatinate the 
** contents to one single string.
*/

char	*multiple_file_list(char *params)
{
	char	**multiple_files;
	char	*file_content;
	size_t	files;
	char	*to_return;
	char	*placeholder;

	to_return = (char*)malloc(sizeof(char));
	files = 0;
	multiple_files = split(params, ',');
	bzero(to_return, sizeof(char));
	while (multiple_files[files])
	{
		file_content = read_ip_file(multiple_files[files]);
		placeholder = join(to_return, file_content);
		free(to_return);
		to_return  = strdup(placeholder);
		free(placeholder);
		free(file_content);
		files++;
	}
	return (to_return);
}

char	**read_file(char *param)
{
	char	*file_cont;
	char	**ip_list;

	if (count_params(param, ',') > 1)
	{
		file_cont = multiple_file_list(param);
	}
	else
	{
		file_cont = read_ip_file(param);
	}
	file_cont = normalize_str(file_cont);
	ip_list = split(file_cont, ' ');
	return (ip_list);
}



