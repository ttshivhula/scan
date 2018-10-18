#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

long long			bintochar(char *binary)
{
	long long		bin_val;
	long long		r;
	long long		total;
	int				i;

	i = 0;
	r = 0;
	total = 0;
	bin_val = atoi(binary);
	while (bin_val > 0)
	{
		r = bin_val % 10;
		bin_val /= 10;
		total += r * pow(2, i);
		i++;
	}
	return (total);
}

int			main(void)
{
	char	open_on[] = "0001";
	char	append_on[] = "1000";
	char	close_on[] = "0100";
	char	our_file[] = "1001";

	long long		file_val = bintochar(our_file);
	long long		open_val = bintochar("0001");
	long long 		append_val = bintochar("1000");
	long long		close_val = bintochar("0100");

	file_val & close_val ? printf("TRUE\n") : printf("FALSE\n");
	file_val & open_val ? printf("TRUE\n") : printf("FALSE\n");


	return (0);

}
