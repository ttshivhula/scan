
#include "parameter.h"

size_t	intlen(size_t size)
{
	size_t		len;

	len = 0;
	while (size > 0)
	{
		size /= 10;
		len++;
	}
	return (len);
}

char	*intostr(size_t size)
{
	char	*intstr;
	size_t	len;

	len = intlen(size);
	intstr = (char*)malloc(sizeof(char) * len + 1);
	intstr[len--] = '\0';
	while (size > 0)
	{
		intstr[len--] = size % 10 + '0';
		size /= 10;
	}
	return (intstr);
}






