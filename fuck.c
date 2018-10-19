#include <netdb.h>
#include <stdio.h>

int 
main(void) {

	struct servent *service;
	service = getservbyport(htons(80), NULL);
	if (service == NULL)
	{
		perror("getservbyport()");
		exit(1);
	}
	printf("service name = %s\n", service->s_name);

	return 0;
}
