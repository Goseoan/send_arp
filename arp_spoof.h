#ifndef __ARPSPOOF_H__
#define __ARPSPOOF_H__

struct getlocal{
	char *mac;
	char *ip;
};

void getLocalAddress(char * , struct getlocal *);
void arp_spoof(int , struct getlocal *,char *, char *, char *);

#endif