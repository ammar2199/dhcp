#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <net/if.h>
#include <net/route.h>

#include <linux/sockios.h>
#include <time.h>
#include <errno.h>
#include <stddef.h>
#include <signal.h>

// TODO:
//  - DNS, Routing Table fix, Script fixes.
//  - Script fixes: Need to add initial route.
//    For some reason route disappears between runs
//  - Add option to deamon-ize.
//      - "-v" - non-daemon, will print too. 
//      - By default should run as daemon
//  - Take notes on Unicast, Multicast, Broadcast for IP.
//  - Take notes on firewall, and firewalld for my project.
//    etc.
//  - Add an ARP check/request once receiving a DHCPACK to make
//    sure IP address is truly free to use.
//  - Mock Tests for Client-Server Interaction.
//  - Add systemd-resolv DBus call 
//    to set DNS, rather than writing to /etc/resolv.conf

#pragma pack(1)
struct dhcp_message {
  uint8_t op, htype, hlen, hops;
  uint32_t xid;
  uint16_t secs, flags;
  uint32_t ciaddr, yiaddr, siaddr, giaddr;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint8_t options[]; // FMA
};
#pragma pack()

#define MESSAGE_SIZE 650

// DHCP Assigned Ports
#define CLIENT_PORT 68
#define SERVER_PORT 67

// Message Direction/Operation
#define BOOTREQUEST 1 // Client to Server
#define BOOTREPLY 2 // Server to Client

#define HARDWARE_ADDRESS_TYPE 1
#define HARDWARE_ADDRESS_SIZE 6 // MAC Address is 6 bytes.

// Option Code/Tag Values
#define PAD 0
#define END 255
#define SUBNET_MASK 1
#define DNS_SERVERS 6 
#define MTU 26
#define BROADCAST_ADDR 28

  // DHCP-Specific
#define REQUESTED_IP 50 
#define LEASE_TIME 51
#define OPTION_OVERLOAD 52 // Unused...
#define DHCP_MESSAGE_TYPE 53
#define SERVER_IDENTIFIER 54
#define MAX_MESSAGE_SIZE 57
// Renewal, Rebinding time?

// Message Types
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNACK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

#define T1_FACTOR 0.5
#define T2_FACTOR 0.85

static const char* Interface = "wlp116s0f4u2";
static const char* DNSConfigFile = "/etc/resolv.conf";

static uint8_t XID[4] = {0xde, 0xad, 0xbe, 0x0ef}; // 0xdeadbeef
static uint8_t MagicCookie[4] = {0x63, 0x82, 0x53, 0x63};

// Initialized with ioctl - SIOCGIFHWADDR
uint8_t MACAddr[HARDWARE_ADDRESS_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static uint32_t ServerIdentifier = 0; // Sent from Server->Client on DHCPOFFER

struct ConfigInfo_t {
  uint32_t LeasedIPAddress; // Assigned IP Address
  uint32_t SubnetMask; // Subnet Mask
  uint32_t DNS[3]; // DNS IP Addresses (up to 3) in network byte-order.
  int NumDNS;

  int LeaseTime; // Time duration the lease is valid; in seconds.
  
  // Absolute Timepoints.
  time_t T0; // Timepoint at which DHCPREQUEST is sent
  time_t T1; // Timepoint to initiate 'Renewing' process.
  time_t T2; // Timepoint to initiate 'Rebinding' process
  time_t T3; // Timepoint when lease expires. // TODO
};

static struct ConfigInfo_t ConfigInfo = {
  .LeasedIPAddress = 0,
  .SubnetMask = 0,
  .NumDNS = 0
};

enum State {
  State_Indeterminate,
  State_InitSelecting,
  State_Requesting,
  State_Bound,
  State_Renewing,
  State_Rebinding,
  State_Fail
};

uint8_t* init_message(struct dhcp_message* const msg) {
  msg->op = BOOTREQUEST;
  msg->htype = HARDWARE_ADDRESS_TYPE;
  msg->hlen = HARDWARE_ADDRESS_SIZE;
  msg->hops = 0;
  memcpy(&msg->xid, XID, sizeof(XID));
  msg->secs = 0;
  msg->flags = 0;
  msg->ciaddr = 0;
  msg->yiaddr = 0;
  msg->siaddr = 0;
  memcpy(msg->chaddr, MACAddr, HARDWARE_ADDRESS_SIZE);
  memset(msg->sname, 0, 64); 
  memset(msg->file, 0, 128);
  memcpy(msg->options, MagicCookie, sizeof(MagicCookie));
  return msg->options + sizeof(MagicCookie);
}

void set_broadcast_flag(struct dhcp_message* msg) {
  msg->flags = htons(0x8000);
}

uint8_t* set_message_type(uint8_t* optionStart, uint8_t msgType) {
  assert(msgType >= 1 && msgType <= 8 && "DHCP Message Type Invalid.");
  optionStart[0] = DHCP_MESSAGE_TYPE;
  optionStart[1] = 1;
  optionStart[2] = msgType;
  return optionStart + 3;
}

uint8_t* set_maximum_message_size(uint8_t* optionStart) {
  optionStart[0] = MAX_MESSAGE_SIZE;
  optionStart[1] = 2;
  uint16_t val = htons(MESSAGE_SIZE);
  memcpy(&optionStart[2], &val, sizeof(val));
  return optionStart + 4;
}

// Note: addr is IPv4 address in network byte-order.
uint8_t* set_requested_ip_address(uint8_t* optionStart, uint32_t addr) {
  optionStart[0] = REQUESTED_IP;
  optionStart[1] = 4;
  memcpy(&optionStart[2], &addr, sizeof(addr));
  return optionStart + 6;
}

// Note: addr is IPv4 address in network byte-order.
uint8_t* set_server_identifier(uint8_t* optionStart, uint32_t addr) {
  optionStart[0] = SERVER_IDENTIFIER;
  optionStart[1] = 4;
  memcpy(&optionStart[2], &addr, sizeof(addr));
  return optionStart + 6;
}

uint8_t* set_end(uint8_t* optionStart) {
  optionStart[0] = END; 
  return optionStart + 1;
}

// Note: DHCP options use a single octet to encode 
//       the option-type, so only 256 possible options.
struct option_map_t {
  uint8_t* options[256];
  uint8_t length[256];
};

void get_options(struct option_map_t* optionMap, const struct dhcp_message* msg) {
  memset(optionMap->options, 0, sizeof(optionMap->options));
  memset(optionMap->length, 0, sizeof(optionMap->length));
  const uint8_t* read = msg->options + sizeof(MagicCookie);
  while ((*read) != END) {
    int optionCode = *read++;
    if (optionCode == PAD) continue;
    int length = *read++;
    optionMap->options[optionCode] = calloc(length, 1);
    memcpy(optionMap->options[optionCode], read, length);
    optionMap->length[optionCode] = length;
    read += length;
  }
}

void free_options(struct option_map_t* optionMap) {
  int elems = sizeof(optionMap->options) / sizeof(optionMap->options[0]);
  for (int i=0; i<elems; i++) {
    if (!optionMap->options[i]) {
      free(optionMap->options[i]);
    }
    optionMap->length[i] = 0;
  }
}

int get_message_type(const struct option_map_t* optionMap) {
  if (!optionMap->options[DHCP_MESSAGE_TYPE] || 
       optionMap->length[DHCP_MESSAGE_TYPE] != 1) {
    return -1;
  }
  uint8_t result = 0;
  memcpy(&result, optionMap->options[DHCP_MESSAGE_TYPE], optionMap->length[DHCP_MESSAGE_TYPE]);
  assert(result >= DHCPDISCOVER && result <= DHCPINFORM && "Unknown Message in Options");
  return result;
}

// Returns Server Identifier in network byte-order.
// If none, returns 0xffffffff
// Note though that this is also ip broadcast addr.
uint32_t get_server_identifer(const struct option_map_t* optionMap) {
  if (!optionMap->options[SERVER_IDENTIFIER] || 
      optionMap->length[SERVER_IDENTIFIER] != 4) {
    return 0xffffffff;
  }
  uint32_t result = 0;
  memcpy(&result, optionMap->options[SERVER_IDENTIFIER], optionMap->length[SERVER_IDENTIFIER]);
  return result;
}

int get_lease_time(const struct option_map_t* optionMap) {
  if (!optionMap->options[LEASE_TIME] ||
      optionMap->length[LEASE_TIME] != 4) {
    return -1;
  }
  uint32_t data = 0;
  memcpy(&data, optionMap->options[LEASE_TIME], optionMap->length[LEASE_TIME]);
  return ntohl(data);
}

// Again, returning 0xfffffff as error.
uint32_t get_subnet_mask(const struct option_map_t* optionMap) {
  if (!optionMap->options[SUBNET_MASK] || 
      optionMap->length[SUBNET_MASK] != 4) {
    return 0xffffffff;
  }
  uint32_t result = 0;
  memcpy(&result, optionMap->options[SUBNET_MASK], optionMap->length[SUBNET_MASK]);
  return result;
}

// Write DNS IPv4 addresses to 'out' and return number of 
// dns servers
uint32_t get_dns_servers(const struct option_map_t* optionMap, uint8_t* out) {
  if (!optionMap->options[DNS_SERVERS] ||
      (optionMap->length[DNS_SERVERS] % 4) != 0) {
    return 0;
  }
  memcpy(out, optionMap->options[DNS_SERVERS], optionMap->length[DNS_SERVERS]);
  return optionMap->length[DNS_SERVERS] / 4;
}

enum State InitSelectingState(const int socketFD, 
                              const struct sockaddr_in* broadcast) {
  enum State nextState = State_Indeterminate;
  printf("Init-Selecting State\n");

  struct dhcp_message* discover = malloc(MESSAGE_SIZE);
  if (!discover) {
    fprintf(stderr, "malloc-failure");
    nextState = State_Fail;
    goto cleanup_discover;
  }
  uint8_t* options = init_message(discover);
  set_broadcast_flag(discover);
  options = set_message_type(options, DHCPDISCOVER);
  options = set_maximum_message_size(options);
  options = set_end(options); 
    
  if ((options - (uint8_t*)(discover)) > MESSAGE_SIZE) {
    fprintf(stderr, "Message Options Overflow!");
    nextState = State_Fail;
    goto cleanup_discover;
  }

  struct dhcp_message* offer = calloc(MESSAGE_SIZE, 1);
  ssize_t bytesSent = 0;
  ssize_t bytesReceived = 0;
  struct option_map_t optionMap;
  uint64_t delay = 2; // We cap delay at >= 32 seconds
  int retries = 5;
  
  //XXX: Move to do-while:
  //     Then I wouldn't need the 'bool receivedData'.
  //     Yea, switch to: do {
  //     } while (nextState != State_Indeterminate)
  
  // Selection Policy: Always choose first valid DHCPOFFER. 
  while (true) {
    bool receivedData = false;
    printf("Init-Selecting State: Sending\n");
    bytesSent = sendto(socketFD, discover, MESSAGE_SIZE, 0 /*flags*/,
                       (struct sockaddr*)broadcast, sizeof(*broadcast));
    if (bytesSent == -1) perror("failed to send");
    while (true) {
      bytesReceived = recv(socketFD, offer, MESSAGE_SIZE, 0 /*flags*/);
      if (bytesReceived == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        if (retries == 0) {
          fprintf(stderr, "Failed to receive Broadcast response");
          nextState = State_Fail;
          goto cleanup_offer;
        }
        printf("Init-Selecting State: Sleeping\n");
        retries--;
        // Delay then Retransmit.
        int jitter = (rand() % 2000) - 1000;
        usleep((delay * 1000) + jitter);
        delay = (delay >= 32) ?  delay : delay * 2; // exponential backoff
        break;
      }
      // XXX: Right now, we're assuming no malicious servers.
      //      but note - this could be infinite.
      //      One possible way around this. Just take a timestamp
      //      right before we enter the loop, If we ever exceed
      //      some time-limit, then log and exit.
      if (memcmp(&offer->xid, XID, sizeof(offer->xid)) != 0) {
        // Retry recv.
        continue;
      }
      get_options(&optionMap, offer);
      if (get_message_type(&optionMap) == DHCPOFFER) {
        printf("Init-Selecting State: Offer Received!\n");
        receivedData = true;
        nextState = State_Requesting;
        break;
      }
      free_options(&optionMap);
    }
    if (receivedData) {
      break;
    }
  }
  
  ServerIdentifier = get_server_identifer(&optionMap);
  ConfigInfo.LeasedIPAddress = offer->yiaddr;
 
  assert(ServerIdentifier != 0xffffffff && "No Server Identifer received in DHCPOFFER");
  assert(ConfigInfo.LeasedIPAddress != 0 && "Invalid 'yiaddr' received in DHCPOFFER");

  struct in_addr givenAddr = {.s_addr = offer->yiaddr};
  printf("Offered IP address: %s\n", inet_ntoa(givenAddr));

    free_options(&optionMap);
cleanup_offer:
    free(offer);
cleanup_discover:
    free(discover);
  return nextState;
}

static int SetIPAddressAndSubnetForInterface(int socketFD, uint32_t ip, uint32_t subnet_mask) {
  // Set IP Address
  struct ifreq interfaceSet;
  strncpy(interfaceSet.ifr_name, Interface, IFNAMSIZ);
  interfaceSet.ifr_name[IFNAMSIZ - 1] = '\0';
  struct sockaddr_in* writer = (struct sockaddr_in*)&interfaceSet.ifr_addr;
  writer->sin_family = AF_INET;
  writer->sin_addr.s_addr = ip;
  if (ioctl(socketFD, SIOCSIFADDR, &interfaceSet) == -1) {
    perror("Failed to set IFADDR");
    return -1;
  }
 
  // Set Subnet Mask
  writer->sin_addr.s_addr = subnet_mask;
  if (ioctl(socketFD, SIOCSIFNETMASK, &interfaceSet) == -1) {
    perror("Failed to set NETMASK");
    return -1;
  }

  return 0;
}

enum State RequestingState(const int socketFD, 
                          const struct sockaddr_in* broadcast) {
  enum State nextState;
  printf("Requesting State\n");

  struct dhcp_message* request = malloc(MESSAGE_SIZE);
  if (!request) {
    fprintf(stderr, "malloc-failure");
    nextState = State_Fail;
    goto cleanup_request;
  }
  uint8_t* options = init_message(request);
  set_broadcast_flag(request);
  options = set_message_type(options, DHCPREQUEST);
  options = set_requested_ip_address(options, ConfigInfo.LeasedIPAddress);
  options = set_server_identifier(options, ServerIdentifier);
  options = set_maximum_message_size(options);
  options = set_end(options);
  
  struct dhcp_message* const response = malloc(MESSAGE_SIZE);

  struct option_map_t optionMap;
  size_t bytesSent = 0;
  size_t bytesReceived = 0;
  int delay = 2;
  int retries = 5;
  time_t sendTime;

  // TODO: Again, I think a do-while loop is what you're looking for,
  while (true) {
    printf("Requesting State: Sending\n");
    bool responseReceived = false;
    time(&sendTime);
    bytesSent = sendto(socketFD, request, MESSAGE_SIZE, 0, 
                      (struct sockaddr*)broadcast, sizeof(*broadcast));
    // XXX: What's happening here?
    if (bytesSent == -1) {
      fprintf(stderr, "Failed to send!!!!");
    }
    while (true) {
      bytesReceived = recv(socketFD, response, MESSAGE_SIZE, 0);
      if (bytesReceived == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        if (retries == 0) {
          fprintf(stderr, "Failed to receive DHCPREQUEST response\n");
          nextState = State_InitSelecting;
          goto cleanup_response;
        }
        printf("Requesting State: Sleeping\n");
        retries--;
        int jitter = (rand() % 2000) - 1000;
        usleep((delay * 1000) + jitter);
        delay = (delay >= 32) ? delay : delay * 2; // exponential backoff
        break; // retransmit
      }
      if (memcmp(XID, &response->xid, sizeof(response->xid))) {
        // Invalid xid. Ignore.
        continue;
      }
      get_options(&optionMap, response);
      if (get_message_type(&optionMap) == DHCPACK) {
        printf("Requesting State: Bound\n");
        responseReceived = true;
        nextState = State_Bound;
        break;
      } else if (get_message_type(&optionMap) == DHCPNACK) {
        // We're also done, but we return to initial state.
        printf("Requesting State: Return to Init-Selecting State\n");
        responseReceived = true;
        nextState = State_InitSelecting;
        free_options(&optionMap);
        goto cleanup_response;
      } else {
        // discard
        free_options(&optionMap);
      }
    }
    if (responseReceived) break;
  }

  ConfigInfo.LeaseTime = get_lease_time(&optionMap);
  ConfigInfo.T0 = sendTime;
  ConfigInfo.T1 = (int)(T1_FACTOR * ConfigInfo.LeaseTime) + ConfigInfo.T0;
  ConfigInfo.T2 = (int)(T2_FACTOR * ConfigInfo.LeaseTime) + ConfigInfo.T0;  
  ConfigInfo.SubnetMask = get_subnet_mask(&optionMap);
  ConfigInfo.NumDNS = get_dns_servers(&optionMap, (uint8_t*)&ConfigInfo.DNS[0]);

  assert(ConfigInfo.LeaseTime != -1 && "No Lease Time received in DHCPACK message");
  assert(ConfigInfo.T2 > ConfigInfo.T1 && "Error: T2 < T1");
  assert(ConfigInfo.T1 > ConfigInfo.T0 && "Error: T1 < T0");
  assert(ConfigInfo.SubnetMask != 0xffffffff && "No Subnet Mask received in DHCPACK message");
  assert(ConfigInfo.NumDNS > 0 && "No DNS name servers received in DHCPACK message");

  printf("Requesting State: Lease-Time %d seconds\n", ConfigInfo.LeaseTime);
  printf("Requesting State: T1-expiration: %s", ctime(&ConfigInfo.T1));
  printf("Requesting State: T2-expiration: %s", ctime(&ConfigInfo.T2));
  struct in_addr printaddr = { .s_addr = ConfigInfo.SubnetMask };
  printf("Requesting State: Subnet Mask: %s\n", inet_ntoa(printaddr));
  for (int i=0; i<ConfigInfo.NumDNS; i++) {
    printaddr.s_addr = ConfigInfo.DNS[i];
    printf("Requesting State: DNS[%d]: %s\n", i, inet_ntoa(printaddr));
  }

  if (SetIPAddressAndSubnetForInterface(socketFD, 
                                        ConfigInfo.LeasedIPAddress, 
                                        ConfigInfo.SubnetMask) != 0) {
    nextState = State_Fail;
  } else {
    // Write DNS Info
    FILE* resolvFile = fopen(DNSConfigFile, "w+"); // XXX: This could fail...
    fprintf(resolvFile, "# Generated by dhcp-daemon\n");
    for (int i=0; i<ConfigInfo.NumDNS; i++) {
      struct in_addr dns = { .s_addr = ConfigInfo.DNS[i] };
      fprintf(resolvFile, "nameserver %s\n", inet_ntoa(dns));
    }
    fclose(resolvFile);

    // Add default entry to gateway in routing table.
    struct rtentry defaultRoute;
    memset(&defaultRoute, 0, sizeof(defaultRoute));

    // Destination Address: "0.0.0.0"
    struct sockaddr_in* set = (struct sockaddr_in*)&defaultRoute.rt_dst;
    set->sin_family = AF_INET;
    set->sin_addr.s_addr = 0;
  
    // Gateway IP = Router IP Address
    set = (struct sockaddr_in*)&defaultRoute.rt_gateway;
    set->sin_family = AF_INET;
    set->sin_addr.s_addr = ServerIdentifier;
    
    // Subnet Mask
    set = (struct sockaddr_in*)&defaultRoute.rt_genmask;
    set->sin_family = AF_INET;
    set->sin_addr.s_addr = 0;

    // Route is Up and is Gateway
    defaultRoute.rt_flags = RTF_UP | RTF_GATEWAY; 
    defaultRoute.rt_dev = strdup(Interface);

    if (ioctl(socketFD, SIOCADDRT, &defaultRoute) == -1) {
      perror("Failed to add default gateway route");
      nextState = State_Fail;
    }
    free(defaultRoute.rt_dev);
  }

  free_options(&optionMap);
cleanup_response:
  free(response);
cleanup_request:
  free(request);
  return nextState;
}

enum State BoundState(const int socketFD,
                      const struct sockaddr_in* broadcast) {
  enum State nextState;
  printf("Bound State\n");
 
  // XXX: CLOCK_REALTIME is tied to Unix Epoch.
  // https://www.gnu.org/software/libc/manual/html_node/Getting-the-Time.html
  int timerFD;
  if ((timerFD = timerfd_create(CLOCK_REALTIME, 0/*flags*/)) == -1) {
    perror("Failed to create Timer");
    nextState = State_Fail;
    goto cleanup_timer;
  }
  
  int epollFD;
  if ((epollFD = epoll_create(1)) == -1) {
    perror("Failed to create epoll");
    nextState = State_Fail;
    goto cleanup_timer;
  }

  struct epoll_event events[2] = {
    { .events = EPOLLIN, .data.fd = socketFD },
    { .events = EPOLLIN, .data.fd = timerFD }
  };
  if (epoll_ctl(epollFD, EPOLL_CTL_ADD, socketFD, &events[0]) == -1) {
    perror("Failed to add socket to epoll");
    nextState = State_Fail;
    goto cleanup_epoll;
  }
  if (epoll_ctl(epollFD, EPOLL_CTL_ADD, timerFD, &events[1]) == -1) {
    perror("Failed to add timer to epoll");
    nextState = State_Fail;
    goto cleanup_epoll;
  }

  // Arm Timer.
  struct itimerspec timerspec = {
    .it_interval = {0, 0},
    .it_value = {.tv_sec = ConfigInfo.T1, .tv_nsec = 0}
  };
  // Set timer to absolute timepoint.
  timerfd_settime(timerFD, TFD_TIMER_ABSTIME, &timerspec, NULL);
  
  struct dhcp_message* rcvMessage = malloc(MESSAGE_SIZE);
  if (!rcvMessage) {
    fprintf(stderr, "malloc-failure");
    nextState = State_Fail;
    goto cleanup_epoll;
  }

  while (true) {
    struct epoll_event event;
    if (epoll_wait(epollFD, &event, 1 /*maxevents*/, -1 /*timeout*/) == -1) {
      perror("epoll_wait");
      nextState = State_Fail;
      break;
    }
    if (event.data.fd == socketFD) {
      printf("Bound State: recv; discarding...\n");
      recv(socketFD, rcvMessage, MESSAGE_SIZE, 0/*flags*/); // Discard all incoming messages.
    } else if (event.data.fd == timerFD) {
      // Time to renew!
      printf("Bound State: Time to Renew!\n");
      nextState = State_Renewing;
      break;
    }
  }

  free(rcvMessage);
cleanup_epoll:
  close(epollFD);
cleanup_timer:
  close(timerFD);
  return nextState;
}

enum State RenewingState(const int socketFD,
                         const struct sockaddr_in* broadcast) {
  enum State nextState;
  printf("Renewing State\n");
  
  struct dhcp_message* request = malloc(MESSAGE_SIZE);
  if (!request) {
    fprintf(stderr, "malloc-failure");
    nextState = State_Fail;
    goto cleanup_request;
  }

  uint8_t* options = init_message(request);
  request->ciaddr = ConfigInfo.LeasedIPAddress;
  options = set_message_type(options, DHCPREQUEST);
  options = set_maximum_message_size(options);
  options = set_end(options);

  struct sockaddr_in unicastAddr = {
    .sin_family = AF_INET,
    .sin_port = htons(SERVER_PORT),
    .sin_addr.s_addr = ServerIdentifier,
  };

  // Create new socket for receiving that's bound to new Client Address.
  // TODO: Store this in ConfigInfo. And only close once lease expires.
  int socketRcv;
  if ((socketRcv = socket(AF_INET, SOCK_DGRAM, 
                          IPPROTO_UDP)) == -1) {
    perror("Failed to create receive socket");
    nextState = State_Fail; 
    goto cleanup_request;
  }
  
  struct timeval recvTimeout;
  recvTimeout.tv_sec = 3;
  recvTimeout.tv_usec = 0;
  if (setsockopt(socketRcv, SOL_SOCKET, SO_RCVTIMEO, 
                 &recvTimeout, sizeof(recvTimeout)) == -1) {
    perror("Failed to set socket recieve timeout");
    nextState = State_Fail;
    goto cleanup_rcvSocket;
  }

  struct sockaddr_in listenAddr = {
    .sin_family = AF_INET,
    .sin_port = htons(CLIENT_PORT),
    .sin_addr.s_addr = ConfigInfo.LeasedIPAddress,
  };
  if ((bind(socketRcv, (struct sockaddr*)&listenAddr, 
                       sizeof(listenAddr)) == -1)) {
    perror("Fail to bind new socket.");
    nextState = State_Fail;
    goto cleanup_rcvSocket;
  }

  size_t bytesSent = 0;
  size_t bytesReceived = 0;
  struct option_map_t optionMap;
  time_t sendTime;

  struct dhcp_message* receivedMsg = malloc(MESSAGE_SIZE);
  if (!receivedMsg) {
    fprintf(stderr, "malloc-failure");
    nextState = State_Fail;
    goto cleanup_rcvSocket;
  }
  
  // do-while aswell.
  while (true) {
    time(&sendTime); 
    if (sendTime > ConfigInfo.T2) {
      nextState = State_Rebinding;
      break;
    }
    bool done = false;
    bytesSent = sendto(socketFD, request, MESSAGE_SIZE, 0/*flags*/,
                       (struct sockaddr*)&unicastAddr, sizeof(unicastAddr));
    while (true) {
      bytesReceived = recv(socketRcv, receivedMsg, MESSAGE_SIZE, 0/*flags*/);
      if (bytesReceived == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        // Retry send.
        // XXX: Ideally, there should be wait here, but just ignore it.
        perror("Failed to recv");
        break;
      }
      // Check if nothing received... 
      if (memcmp(&receivedMsg->xid, &request->xid, sizeof(request->xid)) != 0) {
        continue; // discard.
      }
      get_options(&optionMap, receivedMsg);
      if (get_message_type(&optionMap) == DHCPACK) {
        // Compute new T1, T2, Return to Bounding State
        printf("Renewing-State: ACK\n");
        nextState = State_Bound;
        done = true;
        break;
      } else if (get_message_type(&optionMap) == DHCPNACK) {
        printf("Renewing-State: NACK\n");
        nextState = State_InitSelecting;
        done = true;
        break;
      } else {
        free_options(&optionMap);
      }
    }
    if (done) break;
  }
  
  ConfigInfo.LeaseTime = get_lease_time(&optionMap); 
  ConfigInfo.T0 = sendTime;
  ConfigInfo.T1 = (int)(T1_FACTOR * ConfigInfo.LeaseTime ) + ConfigInfo.T0;
  ConfigInfo.T2 = (int)(T2_FACTOR * ConfigInfo.LeaseTime) + ConfigInfo.T0;
  assert(ConfigInfo.LeaseTime != -1 && "No Lease Time received in DHCPACK message");
  assert(ConfigInfo.T2 > ConfigInfo.T1 && "Error: T2 < T1");
  assert(ConfigInfo.T1 > ConfigInfo.T0 && "Error: T1 < T0");
 
  printf("Renewing State: Lease-Time %d seconds\n", ConfigInfo.LeaseTime);
  printf("Renewing State: T1-expiration: %s", ctime(&ConfigInfo.T1));
  printf("Renewing State: T2-expiration: %s", ctime(&ConfigInfo.T2));

  free_options(&optionMap);
  
  free(receivedMsg);
cleanup_rcvSocket:
  close(socketRcv);
cleanup_request:
  free(request);
  return nextState; 
}


enum State RebindingState(const int socketFD,
                          const struct sockaddr_in* broadcast) {
  //TODO: Unfinished, incomplete
 enum State nextState;
 printf("Rebinding State\n");
 struct dhcp_message* request = malloc(MESSAGE_SIZE);
 uint8_t* options = init_message(request);
 set_broadcast_flag(request);
 request->ciaddr = ConfigInfo.LeasedIPAddress;
 options = set_message_type(options, DHCPREQUEST);
 options = set_maximum_message_size(options);
 options = set_end(options);
 
 struct dhcp_message* receivedMsg = malloc(MESSAGE_SIZE);
  
 time_t sendTime;
 size_t bytesSent = 0;
 size_t bytesReceived = 0;
 struct option_map_t optionMap;
 while (true) {
   time(&sendTime);
   if (sendTime > ConfigInfo.T3) {
      // Clear all network config info
      // and return to Init State.
      nextState = State_Fail;
      break;
   }
   bytesSent = sendto(socketFD, request, MESSAGE_SIZE, 0/*flags*/, 
                      (struct sockaddr*)broadcast, sizeof(*broadcast));
   while (true) {
     bytesReceived = recv(socketFD, request, MESSAGE_SIZE, 0/*flags*/);
    if (bytesReceived == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      perror("Failed to recv");
      break; // resend.
    }
    if (memcmp(&receivedMsg->xid, &request->xid, sizeof(request->xid)) != 0) {
      continue; // discard
    }
    get_options(&optionMap, receivedMsg); 
    if (get_message_type(&optionMap) == DHCPACK) {
      printf("Rebinding-State: ACK\n");
      nextState = State_Bound;
      break;
    } else if (get_message_type(&optionMap) == DHCPNACK) {
      printf("Rebinding-State: NACK\n");
      nextState = State_InitSelecting;
      break;
    } else {
      free_options(&optionMap);
    }
   }
 }

 // TODO: When we move back to INIT-state and we consider 
 //       to no longer control the IP address.
 //       we should set Client.LeasedIPAddress = 0 and
 //       ServerIdentifer = 0
 //       so that signal_handler doesn't try to send DHCPRELEASE until
 //       another one is selected.

 free(request);
 return nextState;
}

static int globalsocketFD; // not ideal

void signal_handler(int signum) {
  printf("signal_handler %d\n", signum);
  const char* msg = "signal handler run %d!\n";
  fprintf(stderr, msg, signum);

  // Graceful shutdown.
  // Send DHCPRELEASE to server
  if (ConfigInfo.LeasedIPAddress != 0) {
    struct dhcp_message* release = malloc(MESSAGE_SIZE);
    uint8_t* options = init_message(release);
    release->ciaddr = ConfigInfo.LeasedIPAddress;
    options = set_message_type(options, DHCPRELEASE);
    options = set_server_identifier(options, ServerIdentifier);
    options = set_end(options);
    struct sockaddr_in unicast = {
      .sin_family = AF_INET,
      .sin_port = htons(SERVER_PORT),
      .sin_addr.s_addr = ServerIdentifier,
    };
    sendto(globalsocketFD, release, MESSAGE_SIZE, 0/*flags*/,
           (struct sockaddr*)&unicast, sizeof(unicast));
    free(release);
  }
  close(globalsocketFD);
  exit(0);
}

int main(int argc, char** argv) {
  time_t processStartTime;
  if (time(&processStartTime) == -1) {
    perror("Failed to get epoch time");
    return -1;
  }
  srand(processStartTime); // Seed RNG
  
  int socketFD;
  if ((socketFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    perror("Failed to open socket");
    return -1;
  }
  globalsocketFD = socketFD;

  signal(SIGINT, signal_handler); // Ctrl-C
  signal(SIGTERM, signal_handler); // systemd-init sends SIGTERM
                                   // on shutdown.
  // Get MAC Address
  struct ifreq interfaceRequest;
  strncpy(interfaceRequest.ifr_name, Interface, IFNAMSIZ);
  interfaceRequest.ifr_name[IFNAMSIZ - 1] = '\0';
  memset(&interfaceRequest.ifr_hwaddr.sa_data, 0, HARDWARE_ADDRESS_SIZE);
  if (ioctl(socketFD, SIOCGIFHWADDR, &interfaceRequest) != 0) {
    perror("Failed to get HW Addr of interface");
    return -1;
  }
  memcpy(MACAddr, interfaceRequest.ifr_hwaddr.sa_data, HARDWARE_ADDRESS_SIZE);


  // TODO: These next few steps are done so we don't have 
  //      to keep running the setup script to put the machine
  //      back in the desired state.
  
  // Remove IP address
  struct sockaddr_in* deleteAddr = (struct sockaddr_in*)&interfaceRequest.ifr_addr;
  deleteAddr->sin_family = AF_INET;
  deleteAddr->sin_port = 0;
  deleteAddr->sin_addr.s_addr = 0;
  if (ioctl(socketFD, SIOCSIFADDR, &interfaceRequest) == -1) {
    perror("Failed to remove IP address of Interface");
    return -1;
  }

  // TODO: Clear Routing Table

  // TODO: Add route so we can send/recieve broadcast packets.
  
  // Bind socket to specific interface.
  if (setsockopt(socketFD, SOL_SOCKET, SO_BINDTODEVICE,
                 Interface, strlen(Interface)) == -1) {
    perror("Failed to set SO_BINDTODEVICE");
    return -1;
  }

  // SO_BROADCAST: Allows datagram sockets to
  // send packets to the broadcast address.
  int broadcastOn = 1;
  if (setsockopt(socketFD, SOL_SOCKET, SO_BROADCAST, 
                 &broadcastOn, sizeof(broadcastOn)) == -1) {
    perror("Failed to set SO_BROADCAST");
    return -1;
  }
  
  // Socket receive timeout.
  struct timeval recvTimeout;
  recvTimeout.tv_sec = 3;
  recvTimeout.tv_usec = 0;
  if (setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, 
                 &recvTimeout, sizeof(recvTimeout)) == -1) {
    perror("Failed to set socket recieve timeout");
    return -1;
  }
 
  struct sockaddr_in sourceAddr;
  sourceAddr.sin_family = AF_INET;
  sourceAddr.sin_port = htons(CLIENT_PORT);
  sourceAddr.sin_addr.s_addr = INADDR_BROADCAST;
  // Bind to port 68 with IP source address as 0.0.0.0
  if (bind(socketFD, (struct sockaddr*)&sourceAddr, 
        sizeof(sourceAddr)) == -1) {
    perror("Failed to bind to address");
    return -1;
  }

  struct sockaddr_in broadcast;
  broadcast.sin_family = AF_INET;
  broadcast.sin_port = htons(SERVER_PORT);
  broadcast.sin_addr.s_addr = INADDR_BROADCAST; // 255.255.255.255
  
  enum State currentState = State_InitSelecting;
  while (currentState != State_Fail) {
    switch (currentState) {
      case State_InitSelecting:
        currentState = InitSelectingState(socketFD, &broadcast);
        break;
      case State_Requesting:
        currentState = RequestingState(socketFD, &broadcast);
        break;
      case State_Bound:
        currentState = BoundState(socketFD, &broadcast);
        break;
      case State_Renewing:
        currentState = RenewingState(socketFD, &broadcast);
        break;
      case State_Rebinding:
        currentState = RebindingState(socketFD, &broadcast); // TODO: Review/Rewrite
        break;
      default:
        fprintf(stderr, "Unknown State Transition\n");
        currentState = State_Fail;
        break;
    }
  }
  
  close(socketFD);
  return 0;
}
