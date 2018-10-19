#ifndef SCAN_H
# define SCAN_H

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <sys/socket.h>
# include <errno.h>
# include <pthread.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip.h>
# include <sys/types.h>
# include <ifaddrs.h>
# include <pcap/pcap.h>
# include <netdb.h>

/*
** Using bitmap for identifying the types of scan needed
*/

# define PKT_LEN	65536
# define NUL 		0x1
# define SYN 		0x2
# define ACK 		0x4
# define FIN 		0x8
# define UDP 		0x10
# define XMS 		0x20
# define ALL 		(NUL|SYN|ACK|FIN|UDP|XMS)

/*
** bitmap values for coordinating flag assignment
*/

# define HELP		1
# define PORTS		2
# define IP		4
# define MFILE		8
# define SPEEDRUN	16
# define SCAN		32

/*
**  hash table for command line argument handling
*/

typedef struct	s_arg
{
	char			*option;
	char			*param;
	struct s_arg		*next;
}		t_keyval;

t_keyval 	*key_value_pair(t_keyval *keyvalue, 
		char *key, char *val);

/*
** Help screen.
*/

void		usage(void);

/*
** basic cmd error message and exit command.
*/

void		error_and_exit(char *msg);

/*
*****
*/

//used for checksum calculation of tcp
typedef struct	s_pseudo
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
}		t_pseudo;

// holds the results of all ports scanned... Do we fucken need a linked list though ?
typedef	struct	s_results
{
	int	port;
	int	syn;
	int	xms;
	int	udp;
	int	nul;
	int	ack;
	int	fin;
	char	s_name[40];
	char	res[20];
	struct s_results *next;
}		t_results;

typedef	struct			s_nmap
{
	int			threads;
	int			type;
	int			port;
	char			source_ip[20];
	char			*d_ip;
	struct sockaddr_in	dest;
	struct	in_addr		dest_ip;
	int			source_port;
	int			sock_fd;
	char			dev[20]; //device used for monitoring //pcap craps
	t_results		*results;
}				t_nmap;

char	*dstip;
char	*srcip;

int				get_local(char *ip, char *device);
void			exit_err(char *s);
char			*dns_lookup(char *addr_host, struct sockaddr_in	*addr_con);
unsigned short	csum(unsigned short *ptr,int nbytes);
void 			recv_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
void			create_pkt(t_nmap *p, char *buff);

/* changes by VHULA */
void		add_ports(t_results **res, int port);
void		open_port(t_results **res, int port, int type, int set);

#endif
