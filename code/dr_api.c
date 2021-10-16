/* Filename: dr_api.c */

/* 	Author: Julian Schilliger
	based on sceleton implementation received for the Networks 2 Project
	Course: Networks, ETH 2019
	version final
*/
/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "dr_api.h"
#include "rmutex.h"

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 20 //was 20
#define RIP_GARBAGE_SEC 20

/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
    uint16_t addr_family;
    uint16_t pad;           /* just put zero in this field */
    uint32_t ip;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t metric;
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
    char        command;
    char        version;
    uint16_t    pad;        /* just put zero in this field */
    rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
    uint32_t subnet;        /* destination subnet which this route is for */
    uint32_t mask;          /* mask associated with this route */
    uint32_t next_hop_ip;   /* next hop on on this route */
    uint32_t outgoing_intf; /* interface to use to send packets on this route */
    uint32_t cost;
    struct timeval last_updated;

    int is_garbage; /* boolean which notes whether this entry is garbage */

    route_t* next;  /* pointer to the next route in a linked-list */
} route_t;


/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;

/* routing table */
static route_t* routingtable = NULL;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/*** Sends specified dynamic routing payload.** @param dst_ip   The ultimate destination of the packet.
 ** @param next_hop_ip  The IP of the next hop (either a router or the final dst).** @param outgoing_intf  Index of the interface to send the packet from.
 ** @param payload  This will be sent as the payload of the DR packet.  The caller*                 is reponsible for managing the memory associated with buf*                 (e.g. this function will NOT free buf).
 ** @param len      The number of bytes in the DR payload.*/
static void (*dr_send_payload)(uint32_t dst_ip,
                               uint32_t next_hop_ip,
                               uint32_t outgoing_intf,
                               char* /* borrowed */,
                               unsigned);


/* internal functions */
long get_time();
long get_time2(struct timeval now);
void print_ip(int ip);
void print_routing_table(route_t *head);
void send_entry(route_t *route);
void send_request(uint32_t outgoing_intf);
void send_request_all();
void send_routing_table(unsigned i);
int update_routing_table(route_t *route);
int clean_routing_table();
void *my_memory(size_t size);
/* internal lock-safe methods for the students to implement */
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                                  char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed);

/*** This simple method is the entry point to a thread which will periodically* make a callback to your dr_handle_periodic method.*/
static void* periodic_callback_manager_main(void* nil) {
    struct timespec timeout;

    timeout.tv_sec = secs_to_sleep_between_callbacks;
    timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
    while(1) {
        nanosleep(&timeout, NULL);
        dr_handle_periodic();
    }

    return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;
    rmutex_lock(&coarse_lock);
    hop = safe_dr_get_next_hop(ip);
    rmutex_unlock(&coarse_lock);
    return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_packet(ip, intf, buf, len);
    rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_periodic();
    rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
    rmutex_lock(&coarse_lock);
    safe_dr_interface_changed(intf, state_changed, cost_changed);
    rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */


void dr_init(unsigned (*func_dr_interface_count)(),
             lvns_interface_t (*func_dr_get_interface)(unsigned index),
             void (*func_dr_send_payload)(uint32_t dst_ip,
                                          uint32_t next_hop_ip,
                                          uint32_t outgoing_intf,
                                          char* /* borrowed */,
                                          unsigned)) {
    pthread_t tid;

    /* save the functions the DR is providing for us */
    dr_interface_count = func_dr_interface_count;
    dr_get_interface = func_dr_get_interface;
    dr_send_payload = func_dr_send_payload;

    /* initialize the recursive mutex */
    rmutex_init(&coarse_lock);

    /* initialize the amount of time we want between callbacks */
    secs_to_sleep_between_callbacks = 1;
    nanosecs_to_sleep_between_callbacks = 0;

    /* start a new thread to provide the periodic callbacks */
    if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
        fprintf(stderr, "pthread_create failed in dr_initn\n");
        exit(1);
    }

    /* do initialization of your own data structures here */
	//set up the routers routing table
	route_t* last = NULL;
	for(unsigned i = 0; i < dr_interface_count(); i++)
	{
		//pick up directly incident routes and save them
		lvns_interface_t interface = dr_get_interface(i);
		if(interface.enabled > 0)
		{
			route_t* next = (route_t*)my_memory(sizeof (route_t));
			next -> outgoing_intf = i;
			gettimeofday(&(next -> last_updated), NULL);
			next -> cost = interface.cost; 
			next -> subnet = ntohl(interface.ip);
			next -> mask = ntohl(interface.subnet_mask);
			next -> next_hop_ip = ntohl(0);
			next -> is_garbage = 0;
			next -> next = NULL;
			
			if(next->cost >= INFINITY)
			{
				free(next);
				continue;
			}
			//saving logic
			if(routingtable == NULL)
			{routingtable = next;
			last = next;}
			else
			{
			last -> next = next;
			last = next;}
		}
	}
	//print_routing_table(routingtable);
}

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
	//initialize hop
    next_hop_t hop;
    hop.interface = 0;
    hop.dst_ip = 0;

    /* determine the next hop in order to get to ip */
	//prepare route, first one gets used if no route was found in the table and sais 'no such route'
	route_t *best2 = (route_t*)my_memory(sizeof (route_t));
	best2 -> outgoing_intf = 0;
	best2 -> cost = INFINITY; 
	best2 -> subnet =  0xFFFFFFFF;
	best2 -> mask = ntohl(0);
	best2 -> next_hop_ip = 0xFFFFFFFF;
	best2 -> is_garbage = 0;
	best2 -> next = NULL;
	route_t *best = best2;

	//try to find longes prefix machting route in routing table, traverse routing table therefore
    route_t *current = routingtable;
    
	//traverse routing table
    while (current != NULL){
	//found longer matching prefix
	if(((((current->mask)&current->subnet) == ((current->mask)&ntohl(ip))) && (best->mask < current->mask)) || ((((current->mask)&current->subnet) == ((current->mask)&ntohl(ip))) && (best->mask == current->mask) && best->cost > current->cost))
	{
		best = current;
	}
        current = current->next;
    }
	//prepare hop data
	hop.interface = best -> outgoing_intf;
	hop.dst_ip = htonl(best -> next_hop_ip);
	//free
	free(best2);
	//printf("hop \n");
	//print_ip(best->next_hop_ip);
    return hop;
}

void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                           char* buf /* borrowed */, unsigned len) {
    /* handle the dynamic routing payload in the buf buffer */

	//check if packet is valid
	lvns_interface_t interface = dr_get_interface(intf);
	if(interface.enabled <= 0)
	{
		//printf("interface is closed, invalid packet \n");
		return;
	}

	//cast packet to right struct
	rip_header_t *pck = (rip_header_t*)my_memory(len);
	memcpy(pck,buf,len);
	//rip_header_t *pck = (rip_header_t *)buf;

	//check for version 2
	if(pck -> version != RIP_VERSION)
	{
		return;
	}

	//check if packet is request for sending routing table
	if(pck -> command == RIP_COMMAND_REQUEST)
	{
		send_routing_table(intf);
		free(pck);
		return;
	}
	//ignore packets that have no route advertisement
	if(pck -> command != RIP_COMMAND_RESPONSE)
	{
		free(pck);
		return;
	}

	//get to the entries
	rip_entry_t *entry = pck -> entries;

	//calculate number of entries
	unsigned number = (len - sizeof (rip_header_t))/ sizeof(rip_entry_t);
	
	//walk trough newly received entries
	for(unsigned i = 0; i < number; i++)
	{
	//prepare msg
	route_t *msg = (route_t*)my_memory(sizeof (route_t));
	msg -> subnet = ntohl(entry -> ip);
	msg -> mask = ntohl(entry->subnet_mask);
	msg -> outgoing_intf = intf;
	msg -> cost = (entry -> metric) + interface.cost;
	msg -> next_hop_ip = ntohl(ip);
	msg -> next = NULL;
	gettimeofday(&(msg -> last_updated), NULL);
	if(msg->cost >= INFINITY)
	{
		msg->cost = INFINITY;
	}

	//insert route into routing table, tell neighbours if something changed
    	update_routing_table(msg);

	//update entry pointer
	entry++;
	}

	//free pck
	free(pck);
	//print_routing_table(routingtable);
}

void safe_dr_handle_periodic() {

	//update all directly incident routes
	for(unsigned i = 0; i < dr_interface_count(); i++)
	{
		//check if interface is alive
		lvns_interface_t interface = dr_get_interface(i);
		if(interface.enabled > 0)
		{
			//build route
			route_t* next = (route_t*)my_memory(sizeof (route_t));
			next -> outgoing_intf = i;
			gettimeofday(&(next -> last_updated), NULL);
			next -> cost = interface.cost; 
			next -> subnet = ntohl(interface.ip);
			next -> mask = ntohl(interface.subnet_mask);
			next -> next_hop_ip = ntohl(0);
			next -> is_garbage = 0;
			next -> next = NULL;

			//insert it, manages memory aswell
			update_routing_table(next);
		}
	}

	//clean routing table
	clean_routing_table();

	//broadcast routing table
	for(unsigned i = 0; i < dr_interface_count(); i++)
	{
		send_routing_table(i);
	}

    /* handle periodic tasks for dynamic routing here */
}

static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed) {
    /* handle an interface going down or being brought up */
	//printf("hoi from intf changed \n");

	//delete all routes associated with the interface intf, all routes out of date
    	route_t *current = routingtable;
    	while (current != NULL){
		if(intf == current->outgoing_intf)
		{
			//delete table entry
			//set time to 0, will get deleted bz clean_routing_table call later in this function
			current->cost = INFINITY;
			
		}
       		current = current->next;
    	}
	//remove marked, bad routes
	clean_routing_table();
	lvns_interface_t interface = dr_get_interface(intf);
	if(interface.enabled > 0)
	{
		//prepare newly accessable route
		route_t *next = (route_t*)my_memory(sizeof (route_t));
		next -> outgoing_intf = intf;
		gettimeofday(&(next -> last_updated), NULL);
		next->cost = interface.cost;
		next -> subnet = ntohl(interface.ip);
		next -> mask = ntohl(interface.subnet_mask);
		next -> next_hop_ip = ntohl(0);
		next -> is_garbage = 0;
		next -> next = NULL;
		
		//insert into routing table, it also manages the memory and tells others if new route is available
		update_routing_table(next);

	}
	//send request, to update all lost routes
	send_request_all();

}

/* definition of internal functions */
//insert route at right place in routing table and sends signals if cost has changed, requests new routes if route was decomissioned(also deletes entry for that route) or got more expensive
//had lvns server crashing on my when causualy allocating memory, now allocate memory for sure
void *my_memory(size_t size)
{
	void *memory = NULL;
	//try allocating until success
	while(memory == NULL) {
	memory = malloc (size);
	}
    	memset (memory, 0, size);
	return memory;
}
int update_routing_table(route_t *route)
{
	if(route -> cost > INFINITY)
	{
		route -> cost = INFINITY;
	}
	//make entry stand alone
	route -> next = NULL;
	
    route_t *current = routingtable;
    route_t *last = NULL;
    int found = 0;
    while (current != NULL){
	if(route->subnet == current->subnet && route->mask == current->mask)
	{
		//found entry
		found = 1;
		//link next element of corresponding probable place in the table to 'route'
		route -> next = current-> next;
		//if cost are smaller or this is the old connection, insert route into the table
		if(route -> cost < current -> cost || (route -> outgoing_intf == current -> outgoing_intf && route -> next_hop_ip == current -> next_hop_ip))
		{
			//printf("insert somewhere \n");
	
			//route cost changed, tell the neighbours
			if(route -> cost != current -> cost && route ->cost != INFINITY)
			{
				send_entry(route);
			}

			//insert route for now
			if(last == NULL)
			{
				routingtable = route;
			}
			else
			{
				last -> next = route;
			}


			//free old entry
			free(current);
			current = route;
		}
		else
		{
			free(route);
		}
		//found entry, processed it, inserted it, can only occur once in table, we may return now from traversing the table
		break;
	}
	else
	{
		last = current;
	}
        current = current->next;
    }
	//insert at the end of the table, since entry was not found
	if(found == 0 && route -> cost < INFINITY)
	{
		found = 1;
		//printf("insert at end \n");
		if(last == NULL)
		{
			routingtable = route;
		}
		else
		{
			last -> next = route;
		}
	}

	if(found == 0)
	{
		free(route);
	}

	//return nr of deleted items, handles route takedowns aswell
	return clean_routing_table();
}//cleans table, sends signals + request if a route was decomissioned
int clean_routing_table()
{
	int cleaned = 0;
	route_t *current = routingtable;
    route_t *last = NULL;
    while (current != NULL){
	if(get_time2(current->last_updated) + RIP_TIMEOUT_SEC*1000 < get_time() || current -> cost >= INFINITY)
	{
		//found bad entry, delete it
		cleaned++;
		if(last == NULL)
		{
			routingtable = current -> next;
		}
		else
		{
			last -> next = current -> next;
		}
		current -> next = NULL;
		//print_routing_table(current);
		//tell neigbours that route is down
		current -> cost = INFINITY;
		send_entry(current);
		//ask neighbours for new route
		send_request_all();
		//free old entry
		free(current);
		//assign current again
		if(routingtable == NULL)
		{
			return cleaned;
		}
		if(last == NULL)
		{
			current = routingtable;
		}
		else
		{
			current = last;
		}
	}
	else
	{
		last = current;
	}
        current = current->next;
    }

	//printf("%d cleaned \n", cleaned);
	return cleaned;
}
void send_routing_table(unsigned i)
{
		//check for valid interface
		lvns_interface_t interface = dr_get_interface(i);
		if(interface.enabled <= 0)
		{
			return;
		}

		//size of routing table to alloc right amount of memory
		route_t *current = routingtable;
		int size = 0;
    		while (current != NULL){
			if(current-> outgoing_intf != i || current -> next_hop_ip == 0)
			{
			size++;
			}
			current = current -> next;
    		}
	
		//alloc memory
		int length = sizeof(rip_entry_t)*size + sizeof (rip_header_t);
		rip_header_t *packet = (rip_header_t*)my_memory(length);
	
		//init header
		packet -> command = RIP_COMMAND_RESPONSE;
		packet -> version = RIP_VERSION;
		packet -> pad = 0;

		//init entries
		rip_entry_t *entry = packet->entries;

		//copy over each routing table entry
		route_t *route = routingtable;
		while (route != NULL){
			if(route-> outgoing_intf != i || route -> next_hop_ip == 0)
			{
			entry ->ip = htonl(route -> subnet);
			entry ->subnet_mask = htonl(route -> mask);
			entry->pad = 0;
			entry->metric = route->cost;
			entry++;
			}
			route = route->next;
		}

		//send command
		dr_send_payload(RIP_IP, RIP_IP, i, (char *)packet, length);
		//free packet again
		free(packet);

}
void send_entry(route_t *route)
{
	rip_header_t *packet = (rip_header_t*)my_memory(sizeof(rip_entry_t) + sizeof (rip_header_t));
	packet -> command = RIP_COMMAND_RESPONSE;
	packet -> version = RIP_VERSION;
	packet -> pad = 0;

	rip_entry_t *entry = packet->entries;
	entry ->ip = htonl(route -> subnet);
	entry ->subnet_mask = htonl(route -> mask);
	entry->pad = 0;
	entry->metric = route->cost;

	for(unsigned i = 0; i < dr_interface_count(); i++)
	{
		lvns_interface_t interface = dr_get_interface(i);
		if(0<interface.enabled && (route-> outgoing_intf != i || route -> next_hop_ip == 0))
		{
			dr_send_payload(RIP_IP, RIP_IP, i, (char *)packet, sizeof(rip_entry_t) + sizeof (rip_header_t));
		}
	}
	//print_ip(ntohl(entry->ip));
	free(packet);
}
void send_request_all()
{
	for(unsigned i = 0; i < dr_interface_count(); i++)
	{
		lvns_interface_t interface = dr_get_interface(i);
		if(0<interface.enabled)
		{
			send_request(i);
		}
	}
}
void send_request(uint32_t outgoing_intf)
{
	rip_header_t *packet = (rip_header_t*)my_memory(sizeof (rip_header_t));
	packet -> command = RIP_COMMAND_REQUEST;
	packet -> version = RIP_VERSION;
	packet -> pad = 0;

	lvns_interface_t interface = dr_get_interface(outgoing_intf);
	if(0<interface.enabled)
	{
		dr_send_payload(RIP_IP, RIP_IP, outgoing_intf, (char *)packet, sizeof(*packet));
	}
	free(packet);
}

// gives current time in milliseconds
long get_time(){
    // Now in milliseconds
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 + now.tv_usec / 1000;
}
long get_time2(struct timeval now){
    // Now in milliseconds
    return now.tv_sec * 1000 + now.tv_usec / 1000;
}

// prints an ip address in the correct format
// this function is taken from: 
// https://stackoverflow.com/questions/1680365/integer-to-ip-address-c 
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

// prints the full routing table
void print_routing_table(route_t *head){
    printf("==================================================================\nROUTING TABLE:\n==================================================================\n");
    int counter = 0;
    route_t *current = head;
    while (current != NULL){
        printf("Entry %d:\n",counter);
        printf("\tSubnet: ");
        print_ip(current->subnet);
        printf("\tMask: ");
        print_ip(current->mask);
        printf("\tNext hop ip: ");
        print_ip(current->next_hop_ip);
        printf("\tOutgoing interface: ");
        print_ip(current->outgoing_intf);
        printf("\tCost: %d\n", current->cost);
        printf("\tLast updated (timestamp in microseconds): %li \n", current->last_updated.tv_usec);
        printf("==============================\n");
        counter ++;

        current = current->next;
    }
}
