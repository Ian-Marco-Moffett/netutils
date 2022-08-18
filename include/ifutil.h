#ifndef IFUTIL_H
#define IFUTIL_H


#include <pcap.h>
#include <stddef.h>


void ifutil_interface_capture(pcap_if_t* interface, const size_t n_packets);
int ifutil_init(void);
void ifutil_uninit(void);
void ifutil_scan(void);
pcap_if_t* ifutil_locate_interface(const char* name);


#endif
