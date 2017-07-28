#ifndef __ARPSPOOF_H__
#define __ARPSPOOF_H__

#define IP_ADDR_SIZE 50
#define MAC_ADDR_SIZE 50

void getLocalAddress(u_int8_t *, u_int8_t *, u_int8_t *, u_int8_t *);
void arp_spoof(u_int8_t *, u_int8_t *, u_int8_t *, u_int8_t *, u_int8_t *, u_int8_t *);

#endif