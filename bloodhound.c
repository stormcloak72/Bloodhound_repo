#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>

pcap_t *handle;

void process_packet(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
  int ether_offset=12;
  int payload_offset=14;
  int payload_length=pkthdr->len-payload_offset;
  unsigned char ip_header_length;

  if (packet[ether_offset]==0x08 && packet[ether_offset+1]==0x00)
  {
    ip_header_length=(packet[payload_offset]&0x0F)*4;
    unsigned char source_ip[4];
    unsigned char dest_ip[4];

    for (int i=0;i<4;++i)
    {
      source_ip[i]=packet[payload_offset+12+i];
      dest_ip[i]=packet[payload_offset+16+i];
    }
    printf("Source IP : %u.%u.%u.%u\n",source_ip[0],source_ip[1],source_ip[2],source_ip[3]);
    printf("Destination IP : %u.%u.%u.%u\n",dest_ip[0],dest_ip[1],dest_ip[2],dest_ip[3]);
    
    unsigned char protocol = packet[payload_offset+9];

    if (protocol==0x06)
    {
      printf("Protocol : TCP\n");

      int tcp_offset=payload_offset+ip_header_length;
      struct tcphdr *tcp_header=(struct tcphdr *)(packet+tcp_offset);
      unsigned char tcp_flags=tcp_header->th_flags;

      if (tcp_flags & TH_SYN)
      {
	      printf("Flags : SYN\n");
      }
      else if ((tcp_flags & TH_SYN) && (tcp_flags & TH_ACK))
      {
	      printf("Flags : SYN-ACK\n");
      }
      else if (tcp_flags & TH_ACK)
      {
	      printf("Flags : ACK\n");
      }
      else if (tcp_flags & TH_FIN)
      {
	      printf("Flags : FIN\n");
      }
      else if (tcp_flags & TH_RST)
      {
	      printf("Flags : RST\n");
      }
      else if (tcp_flags & TH_URG)
      {
	      printf("Flags : URG\n");
      }
      else if (tcp_flags & TH_PUSH)
      {
	      printf("Flags : PUSH\n");
      }
      else if ((tcp_flags & TH_PUSH) && (tcp_flags & TH_SYN))
      {
	      printf("Flags : SYN-PUSH\n");
      }
      else
      {
	      printf("Flags : NONE\n");
      }

      uint32_t seq_num = ntohs(tcp_header->th_seq);
      uint32_t ack_num = ntohs(tcp_header->th_ack);

      printf("Sequence number : %u\n",seq_num);
      printf("Acknowledgement number : %u\n",ack_num);

      unsigned short src_port=(packet[payload_offset+20]<<8) | packet[payload_offset+21];
      unsigned short dest_port=(packet[payload_offset+22]<<8) | packet[payload_offset+23];

      printf("Source port : %u\n",src_port);
      printf("Destination port : %u\n",dest_port);
    }

    else if (protocol==0x01)
    {
      printf("Protocol : ICMP\n");
    }

    else if (protocol==0x11)
    {
      printf("Protocol : UDP\n");
      unsigned short src_port=(packet[payload_offset+20]<<8) | packet[payload_offset+21];
      unsigned short dest_port=(packet[payload_offset+22]<<8) | packet[payload_offset+23];

      printf("Source port : %u\n",src_port);
      printf("Destination port : %u\n",dest_port);
    }

    unsigned char ttl=packet[payload_offset+8];
    printf("TTL value : %u\n",ttl);

    unsigned short window_size = (packet[payload_offset+ip_header_length+14]<<8) | packet[payload_offset+ip_header_length+15];
    printf("Window size : %u\n",window_size);
      
    unsigned char flags=packet[payload_offset+6];

    if (flags&0x40)
    {
      printf("Fragmentation : NO\n");
    }
    else
    {
      printf("Fragmentation : YES\n");
    }

    if (ip_header_length > 20)
    {
	    unsigned char options_length = ip_header_length - 20;
	    printf("Options length : %u bytes\n",options_length);

	    for (int i=0; i < options_length;)
	    {
		    printf("Option type : %u\n", packet[payload_offset+20+i]);

		    if (packet[payload_offset+20+i] !=0)
		    {
			    unsigned char option_length = packet[payload_offset+20+i+1];

			    printf("Option length : %u bytes\n", option_length);

			    printf("Option data : ");
			    for (int j=0; j<option_length - 2; ++j)
			    {
				    printf("%02X ", packet[payload_offset+20+i+2+j]);
			    }
			    printf("\n");
			    i+=option_length;
		    }

		    else
		    {
			    printf("Option data : NONE\n");
			    break;
		    }
	    }
    }
  }


  printf("Packet length : %d\n",pkthdr->len);
  if (payload_length>0)
  {
    printf("Payload: ");
    for (int i=0; i < payload_length; i++)
    {
      if (isprint(packet[payload_offset+i]))
      {
        printf("%c ", packet[payload_offset+i]);
      }
    }
    printf("\n\n");
  }
}

void signal_alpha(int sig)
{
  printf("\nThank you for using Bloodhound!!\n\n");
}

void signal_beta(int sig)
{
  printf("\nThank you for using Bloodhound!!\n\n");
  pcap_close(handle);
}

int main()
{
  signal(SIGINT, signal_alpha);
  system("cat banner.txt");
  printf("\n\033[1;33m* A ethernet packet capturing utility written in C by Chi_Tianshi *\033[1;0m\n");
  printf("\n\033[1;37m-------------------------------------------------------------------\033[1;0m");
  char errbuf[PCAP_ERRBUF_SIZE];
  char device[]="eth0";
  pcap_if_t *ldev;

  if (pcap_findalldevs(&ldev, errbuf)== -1)
  {
    printf("Error while finding available devices...-> %s\n", errbuf);
    return 1;
  }

  //pcap_if_t *devs;
  //char* mydev;
  //int i=0;
  //printf("Please select a device to sniff on from below...\n\n");
  //for (devs=ldev; devs; devs=devs->next)
  //{
    //mydev=strdup(devs->name);
    //if (mydev=="eth0")
    //{
      //i=1;
    //}
    //printf("-> %s\n", mydev);
  //}
  //if (i==0)
  //{
    //printf("\033[1;31mSorry! Bloodhound only supports ethernet packet capturing for now!\033[1;0m\n\n");
    //return 1;
  //}
  //pcap_freealldevs(ldev);

  signal(SIGINT, signal_beta);
  //printf("\nEnter the name of device : ");
  //scanf("%s",device);
  printf("\n\033[1;33mOpening handle for device : %s\033[1;0m\n",device);
  
  handle = pcap_create(device, errbuf);
  if (handle==NULL)
  {
    printf("\033[1;31mError while creating handle : %s\033[1;0m\n",errbuf);
    return 1;
  }
  printf("\033[1;33mHandle creation successfull!\033[1;0m\n");

  if (pcap_activate(handle)!=0)
  {
    printf("\n\033[1;31mError while activating handle -> %s\033[1;0m\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }
  printf("\033[1;33mHandle activation successfull!\033[1;0m\n");
  printf("\033[1;33mPacket capture on!\033[1;0m\n\n");

  if (pcap_loop(handle, 0, process_packet, NULL)<0)
  {
    printf("\n\033[1;31mError while capturing packets -> %s\033[1;0m\n", pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  pcap_close(handle);

}
