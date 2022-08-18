#include <ifutil.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>

static pcap_if_t* devs;

static void get_dev_info(pcap_if_t* dev) {
    char* description = dev->description != NULL ? dev->description : "No description.";
    char* address;

    if (dev->addresses != NULL) {
      address = inet_ntoa(((struct sockaddr_in*)(dev->addresses->addr))->sin_addr);
    } else {
      address = NULL;
    }
    
    if (address == NULL) {
      address = "Unknown.";
    }

    printf("Device \"%s\" found:\n", dev->name);
    printf("Description => %s\n", description);
    printf("Address => %s\n\n", address);
}




void ifutil_interface_capture(pcap_if_t* interface, const size_t n_packets) {
  char error_buf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(interface->name, BUFSIZ, n_packets, 10000, error_buf);

  if (handle == NULL) {
    printf("Failed to capture.\n");
    perror(interface->name);
    return;
  }

  printf("Capturing packets, please wait..\n");
  for (int i = 0; i < n_packets; ++i) {
    struct pcap_pkthdr packet_header;
    const u_char* packet = pcap_next(handle, &packet_header);

    if (packet != NULL) {
      printf("\nPacket capture length => %d\n", packet_header.caplen);
      printf("Packet total length => %d\n", packet_header.len);
      printf("Packet data => 0x%x\n\n", *packet);
    }
  }

  pcap_close(handle);
}


pcap_if_t* ifutil_locate_interface(const char* name) {
  pcap_if_t* cur = devs;

  while (cur != NULL) {
    if (cur->name != NULL) {
      if (strcmp(cur->name, name) == 0) {
        return cur;
      }
    }

    cur = cur->next;
  }

  return NULL;
}


int ifutil_init(void) {
  char error_buf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&devs, error_buf) != 0) {
    printf("Error finding a device!: %s\n", error_buf);
    return 1;
  }

  return 0;
}


void ifutil_uninit(void) {
  pcap_freealldevs(devs);
}


/*
 *  Lists all interfaces.
 *
 */

void ifutil_scan(void) {
  pcap_if_t* cur = devs;

  while (cur != NULL) {
    get_dev_info(cur);
    cur = cur->next;
  }
}
