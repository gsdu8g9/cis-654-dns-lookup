/*
 *
 *  CIS 654 Networking Project - DNS Lookup
 *  Niko Solihin
 *  Grand Valley State University
 *
 */
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>

// List of DNS Servers
char dns_servers[25][100];
char dns_servernames[25][100];
int dns_servercount = 13;

// Type field of Query and Answer
#define T_A		    1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_CNAME		5		/* canonical name */
#define T_SOA		6		/* start of authority zone */
#define T_PTR		12		/* domain name pointer */
#define T_MX		15		/* mail routing information */

// Flag
int done = 0;

// Function Prototypes
void ngethostbyname (unsigned char* , int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();

// DNS header structure
struct DNS_HEADER {
	unsigned	short id;		    // identification number
	
	unsigned	char rd     :1;		// recursion desired
	unsigned	char tc     :1;		// truncated message
	unsigned	char aa     :1;		// authoritive answer
	unsigned	char opcode :4;	    // purpose of message
	unsigned	char qr     :1;		// query/response flag
	
	unsigned	char rcode  :4;	    // response code
	unsigned	char cd     :1;	    // checking disabled
	unsigned	char ad     :1;	    // authenticated data
	unsigned	char z      :1;		// its z! reserved
	unsigned	char ra     :1;		// recursion available
	
	unsigned    short q_count;	    // number of question entries
	unsigned	short ans_count;	// number of answer entries
	unsigned	short auth_count;	// number of authority entries
	unsigned	short add_count;	// number of resource entries	
};

// Constant sized fields of query structure
struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};

// Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA {
	unsigned short type;
	unsigned short _class;
	unsigned int   ttl;
	unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD {
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

// Structure of a Query
typedef struct {
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

int main( int argc , char *argv[]) {
    
	unsigned char hostname[100];

    // Initialize the DNS Server list from http://www.internic.net/zones/named.root
    get_dns_servers();  

	// Get hostname from user
	printf("\nEnter Hostname to lookup: ");
	scanf("%s" , hostname);

    while(!done) {
	    // Get the IP of this hostname until answer records are received
	    ngethostbyname(hostname , T_A);
    }
	return 0;
}

/*
 *  Perform a DNS query by sending a packet
 */
void ngethostbyname(unsigned char *host , int query_type) {
    
	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s, random_server;
	
    srand ( time(NULL) );                               // Initialize Random Seed
    random_server = rand() % dns_servercount;           // Pick a random nameserver

	struct sockaddr_in a;

	struct RES_RECORD answers[20],auth[20],addit[20];   //The replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);     //UDP packet for DNS queries

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_servers[random_server]); 

	// Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; 
	dns->opcode = 0; 
	dns->aa = 0; 
	dns->tc = 0; 
	dns->rd = 1; 
	dns->ra = 0; 
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); 
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	// Query Portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname , host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];

	qinfo->qtype = htons( query_type ); 
	qinfo->qclass = htons(1); 

	printf("\nSending Packet to %s (%s) ... " , dns_servernames[random_server], dns_servers[random_server]);
	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("sendto failed");
	}
	printf("Done");

	// Receive the response
	i = sizeof dest;
	printf("\nResponse Record Received ... ");
	if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
	}
	printf("Done");

	dns = (struct DNS_HEADER*) buf;

	//The Query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	printf("\nThe response contains : ");
	printf("\n\t %d Questions.",ntohs(dns->q_count));
	printf("\n\t %d Answers.",ntohs(dns->ans_count));
	printf("\n\t %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n\t %d Additional records.\n",ntohs(dns->add_count));

	// Start Reading Answers
	stop=0;

	for(i=0;i<ntohs(dns->ans_count);i++)
	{
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1)           //If it's an ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		}
		else
		{
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	// Read authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		auth[i].rdata=ReadName(reader,buf,&stop);
		reader+=stop;
	}

	// Read additional
	for(i=0;i<ntohs(dns->add_count);i++)
	{
		addit[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		if(ntohs(addit[i].resource->type)==1)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
			addit[i].rdata=ReadName(reader,buf,&stop);
			reader+=stop;
		}
	}

	// Print Answers
    int answer_count = ntohs(dns->ans_count);
	printf("\nAnswer Records : %d \n" , answer_count );
	for(i=0 ; i < answer_count ; i++)
	{
		printf("%s  ",answers[i].name);
        printf("%d   ",answers[i].resource->ttl);
		if( ntohs(answers[i].resource->type) == T_A)        // IPv4 address
		{
			long *p;
			p=(long*)answers[i].rdata;
			a.sin_addr.s_addr=(*p); 
			printf("IN  NS  %s",inet_ntoa(a.sin_addr));
		}

		if(ntohs(answers[i].resource->type)==5)
		{
			//CNAME for an alias
			printf("IN CNAME  %s",answers[i].rdata);
		}

		printf("\n");
	}

	// Print Authorities
	printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
	for( i=0 ; i < ntohs(dns->auth_count) ; i++)
	{
		printf("%s  ",auth[i].name);
        printf("%d  ",auth[i].resource->ttl);
		if(ntohs(auth[i].resource->type)==2)
		{
			printf("IN  NS  %s",auth[i].rdata);
		}
		printf("\n");
	}

	// Print Additional Resource Records
	dns_servercount = ntohs(dns->add_count);
	printf("\nAdditional Records : %d \n" , dns_servercount );
	for(i=0; i < dns_servercount ; i++)
	{
		printf("%s  ",addit[i].name);
		if(ntohs(addit[i].resource->type)==1)
		{
			long *p;
			p=(long*)addit[i].rdata;
			a.sin_addr.s_addr=(*p);
            const char* temp_ip = inet_ntoa(a.sin_addr);
            const char* temp_name = addit[i].name;
			printf("IN  A  %s", temp_ip);
			strcpy(dns_servers[i] , temp_ip);
			strcpy(dns_servernames[i] , temp_name);
		}
		printf("\n");
	}
	
    // Raise flag if answer records were received
    if( answer_count > 0 ) {
        done = 1;
    } else {    //information for next iteration
        printf("\nNo answer record received - Picking a nameserver above at random ...\n");
    }
}

/*
 *  Read DNS Name Format and Convert Back
 */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;
	*count = 1;
	name = (unsigned char*)malloc(256);
	name[0]='\0';

	// Read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152;   // 49152 = 11000000 00000000
			reader = buffer + offset - 1;
			jumped = 1;                                     // Jump to another location so counting wont go up
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1;    // Haven't jumped to another location so we can count up
		}
	}
	name[p]='\0';                   // String complete
	if(jumped==1)
	{
		*count = *count + 1;        // Number of steps we actually moved forward in the packet
	}

	// Convert back 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++)
	{
		p=name[i];
		for(j=0;j<(int)p;j++)
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0';             // Remove the last dot
	return name;
}

/*  
 * DNS Servers from http://www.internic.net/zones/named.root 
 */
void get_dns_servers() {
    strcpy(dns_servers[0] , "198.41.0.4");              // A.ROOT-SERVERS.NET
    strcpy(dns_servernames[0] , "A.ROOT-SERVERS.NET");
    strcpy(dns_servers[1] , "192.228.79.201");          // B.ROOT-SERVERS.NET
    strcpy(dns_servernames[1] , "B.ROOT-SERVERS.NET");
    strcpy(dns_servers[2] , "192.33.4.12");             // C.ROOT-SERVERS.NET
    strcpy(dns_servernames[2] , "C.ROOT-SERVERS.NET");
    strcpy(dns_servers[3] , "128.8.10.90");             // D.ROOT-SERVERS.NET
    strcpy(dns_servernames[3] , "D.ROOT-SERVERS.NET");
    strcpy(dns_servers[4] , "192.203.230.10");          // E.ROOT-SERVERS.NET
    strcpy(dns_servernames[4] , "E.ROOT-SERVERS.NET");
    strcpy(dns_servers[5] , "192.5.5.241");             // F.ROOT-SERVERS.NET
    strcpy(dns_servernames[5] , "F.ROOT-SERVERS.NET");
    strcpy(dns_servers[6] , "192.112.36.4");            // G.ROOT-SERVERS.NET
    strcpy(dns_servernames[6] , "G.ROOT-SERVERS.NET");
    strcpy(dns_servers[7] , "128.63.2.53");             // H.ROOT-SERVERS.NET
    strcpy(dns_servernames[7] , "H.ROOT-SERVERS.NET");
    strcpy(dns_servers[8] , "192.36.148.17");           // I.ROOT-SERVERS.NET
    strcpy(dns_servernames[8] , "I.ROOT-SERVERS.NET");
    strcpy(dns_servers[9] , "192.58.128.30");           // J.ROOT-SERVERS.NET
    strcpy(dns_servernames[9] , "J.ROOT-SERVERS.NET");
    strcpy(dns_servers[10] , "193.0.14.129");           // K.ROOT-SERVERS.NET
    strcpy(dns_servernames[10] , "K.ROOT-SERVERS.NET");
    strcpy(dns_servers[11] , "199.7.83.42");            // L.ROOT-SERVERS.NET
    strcpy(dns_servernames[11] , "L.ROOT-SERVERS.NET");
    strcpy(dns_servers[12] , "202.12.27.33");           // M.ROOT-SERVERS.NET
    strcpy(dns_servernames[12] , "M.ROOT-SERVERS.NET");
}

/*
 * Convert www.google.com to 3www6google3com 
 */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++)
	{
		if(host[i]=='.')
		{
			*dns++ = i-lock;
			for(;lock<i;lock++)
			{
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++='\0';
}
