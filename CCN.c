#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
 
#include<netinet/ip_icmp.h>//Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<pcap.h> //For accessing pcap libraries
#include<time.h> //For time function

typedef struct arphdr {
u_int16_t htype; /* Hardware Type */
u_int16_t ptype; /* Protocol Type */
u_char hlen; /* Hardware Address Length */
u_char plen; /* Protocol Address Length */
u_int16_t oper; /* Operation Code */
u_char sha[6]; /* Sender hardware address */
u_char spa[4]; /* Sender IP address */
u_char tha[6]; /* Target hardware address */
u_char tpa[4]; /* Target IP address */
}arphdr_t;

#define MAXBYTES2CAPTURE 2048
#define ARP_REQUEST 1 /* ARP Request */
#define ARP_REPLY 2 /* ARP Reply */
 
void Process_Packet(unsigned char* , int); //Processes the packet
void Ip_header(unsigned char* , int); //Printing IP header
void Tcp_packet(unsigned char * , int ); //For tcp packet
void Udp_packet(unsigned char * , int ); //For udp packet
void Icmp_packet(unsigned char* , int ); //For icmp packet
void Print_Data (unsigned char* , int);
void Arp_packet(); //For arp packet
clock_t start_time,end_time;
FILE *fileptr; //File pointer for accessing logfile
FILE *fp; //File pointer for accessing the final.csv file

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,arp=0,others=0,igmp=0,total=0,i,j; //Initialization of variables

char *argv="eth0"; //Specifying the network interface
bpf_u_int32 netaddr=0, mask=0; /* To Store network address and netmask */
struct bpf_program filter; /* Place to store the BPF filter program */
char errbuf[PCAP_ERRBUF_SIZE]; /* Error buffer */
pcap_t *descr = NULL; /* Network interface handler */
struct pcap_pkthdr pkthdr; /* Packet information (timestamp,size...) */
const unsigned char *packet=NULL; /* Received raw data */
arphdr_t *arpheader = NULL; /* Pointer to the ARP header */
 
 
int main()
{
   
   
    memset(errbuf,0,PCAP_ERRBUF_SIZE); //Fill block of memory
    int saddr_size , data_size;
    struct sockaddr saddr; //sockaddr and in_addr are used to access internet addresses
    struct in_addr in;
         
    unsigned char *buffer = (unsigned char *) malloc(65536); 
     
   fileptr=fopen("log.txt","w");
    if(fileptr==NULL)
    {
        printf("Unable to create log.txt file.");
    }

    fp = fopen("final.csv", "a");
    if(fp == NULL)
   	 printf("Couldn't open file\n");
    fprintf(fp,"TCP,ICMP,UDP,ARP,TOTAl\n");
    fclose(fp);

    printf("Starting...\n");
    
    start_time=clock();
    
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ; //create a socket for sending receiving datagrams
    
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        Process_Packet(buffer , data_size);
	
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
void Process_Packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly
        {
        case 1:  //ICMP Protocol
            ++icmp;
            Icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            Tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            Udp_packet(buffer , size);
            break;
         
        default:  //ARP Protocol
	    Arp_packet();
            ++arp;
            break;
}

	end_time=clock();
	int diff_time=end_time-start_time;
    
	if(diff_time/20000>=60)

		{fp = fopen("final.csv", "a");
		if(fp == NULL)
			printf("Couldn't open file\n");
		fprintf(fp, "%d,%d,%d,%d,%d\n",tcp,icmp,udp,arp,total);
		fclose(fp);
		start_time=clock();
		}
		printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   ARP : %d   Total : %d\r", tcp , udp , icmp , igmp , arp , total);
}
 
void print_ethernet_header(unsigned char* Buffer, int Size)
{
struct ethhdr *eth = (struct ethhdr *)Buffer;
     
	fprintf( fileptr, "\n");
	fprintf( fileptr , "Ethernet Header\n");
	fprintf( fileptr , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf( fileptr , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf( fileptr , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
 
void Ip_header(unsigned char* Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);
		   
	unsigned short iphdrlen;
			 
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
		     
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
		     
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
		     
	fprintf(fileptr , "\n");
	fprintf(fileptr , "IP Header\n");
	fprintf(fileptr , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(fileptr, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(fileptr , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(fileptr, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(fileptr , "   |-Identification    : %d\n",ntohs(iph->id));
	fprintf(fileptr , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(fileptr , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(fileptr , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(fileptr , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(fileptr , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
 

void Arp_packet()
{	
	
	descr = pcap_open_live(argv, MAXBYTES2CAPTURE, 0, 512, errbuf);
	fprintf(fileptr,"\n\n***********************ARP Packet*************************\n");
	
	if ( (packet = pcap_next(descr,&pkthdr)) == NULL){ /* Get one packet */
	fprintf(stderr, "ERROR: Error getting the packet.\n", errbuf);
	exit(1);
	}
	arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */
	fprintf(fileptr,"\n\nReceived Packet Size: %d bytes\n", pkthdr.len);
	fprintf(fileptr,"Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
	fprintf(fileptr,"Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
	fprintf(fileptr,"Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");
	// If is Ethernet and IPv4, print packet contents
	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
	fprintf(fileptr,"Sender MAC: ");
	for(i=0; i<6;i++)
	fprintf(fileptr,"%02X:", arpheader->sha[i]);
	fprintf(fileptr,"\nSender IP: ");
	for(i=0; i<4;i++)
	fprintf(fileptr,"%d.", arpheader->spa[i]);
	fprintf(fileptr,"\nTarget MAC: ");
	for(i=0; i<6;i++)
	fprintf(fileptr,"%02X:", arpheader->tha[i]);
	fprintf(fileptr,"\nTarget IP: ");
	for(i=0; i<4; i++)
	fprintf(fileptr,"%d.", arpheader->tpa[i]);
	fprintf(fileptr,"\n");
	}
	
	fprintf(fileptr,"\n###########################################################");
}

void Tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(fileptr , "\n\n***********************TCP Packet*************************\n"); 
         
    Ip_header(Buffer,Size);
         
    fprintf(fileptr , "\n");
    fprintf(fileptr , "TCP Header\n");
    fprintf(fileptr , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(fileptr , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(fileptr , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(fileptr , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(fileptr , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(fileptr , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(fileptr , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(fileptr , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(fileptr , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(fileptr , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(fileptr , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(fileptr , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(fileptr , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(fileptr , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(fileptr , "\n");
    fprintf(fileptr , "                        DATA Dump                         ");
    fprintf(fileptr , "\n");
         
    fprintf(fileptr , "IP Header\n");
    Print_Data(Buffer,iphdrlen);
         
    fprintf(fileptr , "TCP Header\n");
    Print_Data(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(fileptr , "Data Payload\n");   
    Print_Data(Buffer + header_size , Size - header_size );
                         
    fprintf(fileptr , "\n###########################################################");
}
 
void Udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    fprintf(fileptr , "\n\n***********************UDP Packet*************************\n");
     
    Ip_header(Buffer,Size);          
     
    fprintf(fileptr , "\nUDP Header\n");
    fprintf(fileptr , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(fileptr , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(fileptr , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(fileptr , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(fileptr , "\n");
    fprintf(fileptr , "IP Header\n");
    Print_Data(Buffer , iphdrlen);
         
    fprintf(fileptr , "UDP Header\n");
    Print_Data(Buffer+iphdrlen , sizeof udph);
         
    fprintf(fileptr , "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    Print_Data(Buffer + header_size , Size - header_size);
     
    fprintf(fileptr , "\n###########################################################");
}
 
void Icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(fileptr , "\n\n***********************ICMP Packet*************************\n");
     
    Ip_header(Buffer , Size);
             
    fprintf(fileptr , "\n");
         
    fprintf(fileptr , "ICMP Header\n");
    fprintf(fileptr , "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(fileptr , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(fileptr , "  (ICMP Echo Reply)\n");
    }
     
    fprintf(fileptr , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(fileptr , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    
    fprintf(fileptr , "\n");
 
    fprintf(fileptr , "IP Header\n");
    Print_Data(Buffer,iphdrlen);
         
    fprintf(fileptr , "UDP Header\n");
    Print_Data(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(fileptr , "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    Print_Data(Buffer + header_size , (Size - header_size) );
     
    fprintf(fileptr , "\n###########################################################");
}
 
void Print_Data (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(fileptr , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(fileptr , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(fileptr , "."); //otherwise print a dot
            }
            fprintf(fileptr , "\n");
        }
         
        if(i%16==0) fprintf(fileptr , "   ");
            fprintf(fileptr , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(fileptr , "   "); //extra spaces
            }
             
            fprintf(fileptr , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(fileptr , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(fileptr , ".");
                }
            }
             
            fprintf(fileptr ,  "\n" );
        }
    }
}
