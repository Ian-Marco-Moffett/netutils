#include <pcap.h>
#include <argp.h>
#include <ifutil.h>
#include <stdint.h>
#include <stdlib.h>


/*
 *  Command argument keys (i.e stuff like '-s')
 *
 */

typedef enum {
  ARG_KEY_IFSCAN = 's',
  ARG_KEY_IFCAP = 'c',
  ARG_KEY_IF = 'i',
  ARG_KEY_N_PACKETS = 'n',
} CMD_ARG_KEY;


/*
 *  Flags the make the program run
 *  in different ways!
 *
 */

typedef enum {
  FLAG_IFSCAN = (1 << 0),
  FLAG_IFCAP = (1 << 1)
} FLAGS;


static uint16_t flags = 0;


static struct argp_option options[] = {
  {"ifscan", ARG_KEY_IFSCAN, 0, 0, "Scans for network interfaces"},
  {"interface", ARG_KEY_IF, "INTERFACE", 0, "Target interface"},
  {"npackets", ARG_KEY_N_PACKETS, "PACKET COUNT", 0, "Used when capturing packets."},
  {"ifcap", ARG_KEY_IFCAP, 0, 0, "Captures data on an interface"},
  {0}
};


static const char* interface = NULL;
static const char* n_packets = NULL;             // Used when capturing packets (how many packets to capture).


static int parse_opt(int key, char* arg, struct argp_state* state) {
  switch (key) {
    case ARG_KEY_IFSCAN:
      flags |= FLAG_IFSCAN;
      break;
    case ARG_KEY_IFCAP:
      flags |= FLAG_IFCAP;
      break;
    case ARG_KEY_IF:
      interface = arg;
      break;
    case ARG_KEY_N_PACKETS:
      n_packets = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}


/*
 *  Checks if an interface was specified and 
 *  if it exists, if so, return that interface.
 *  Otherwise, give an error message.
 *
 *
 */


static pcap_if_t* get_if(void) {
  if (interface == NULL) {
      printf("Interface not specified! Use --help\n");
      return NULL;
    }

    pcap_if_t* pcap_if = ifutil_locate_interface(interface);

    if (pcap_if == NULL) {
      printf("Interface \"%s\" not found!\n", interface);
      return NULL;
    }

    return pcap_if;
}


/*
 *  Dumps device info to the console.
 *
 */


static int run(void) {
  // Init interface util.
  ifutil_init(); 

  if (flags & FLAG_IFSCAN) {
    ifutil_scan();
  }

  if (flags & FLAG_IFCAP) {
    // Capture interface if no error.
    pcap_if_t* pcap_if = get_if();

    if (pcap_if == NULL) {
      ifutil_uninit();
      return 1;
    }

    size_t packet_count;

    if (n_packets == NULL) {
      printf("Please use --npackets <n_packets>\nTry passing --help for more info.\n");
      ifutil_uninit();
      return 1;
    } else {
      packet_count = atoi(n_packets);
    }

    ifutil_interface_capture(pcap_if, packet_count);
  }

  // Cleanup.
  ifutil_uninit();
  return 0;
}


int main(int argc, char** argv) {
  if (argc < 2) {
    printf("Too few arguments! Use --help or --usage\n");
    return 1;
  }

  struct argp argp = {options, parse_opt};
  argp_parse(&argp, argc, argv, 0, 0, 0);

  return run();
}
