#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "string.h"
// Ethernet types set as defines
#define ETHERNET_IPV4 0x0800
#define ETHERNET_ARP 0x0806

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *artable;
int arp_table_len;

queue waiting;

struct arp_data
{
	int length;
	char *buff;
};
/* Comparator used for qsort, it sorts the rtable elements by applying each mask to it's prefix and comaprign them
in the case that they are equal it sorts them based on the mask*/
int comparator(const void *first, const void *second)
{
	uint32_t f = ((struct route_table_entry *)first)->prefix;
	uint32_t s = ((struct route_table_entry *)second)->prefix;

	uint32_t m1 = ((struct route_table_entry *)first)->mask;
	uint32_t m2 = ((struct route_table_entry *)second)->mask;

	int final = (f & m1) - (s & m2);
	if (final != 0)
	{
		return final;
	}

	return (int)(m1 - m2);
}
/* Recursive binary search, it compares the given ip to thie route table entry, after applying the entry's
mask to both of them*/
struct route_table_entry *binary(uint32_t ip_dest, int low, int high, struct route_table_entry *prev)
{
	int mid = (low + high) / 2;
	if (((ip_dest)&rtable[mid].mask) == (rtable[mid].prefix & rtable[mid].mask))
	{
		if (low == high)
		{
			return &rtable[mid];
		}
		if (low > high)
		{
			return prev;
		}

		return binary(ip_dest, mid + 1, high, &rtable[mid]);
	}
	else if (((ip_dest)&rtable[mid].mask) < (rtable[mid].prefix & rtable[mid].mask))
	{
		return binary(ip_dest, low, mid - 1, prev);
	}
	else if (low >= high)
	{
		return prev;
	}
	else
	{
		return binary(ip_dest, mid + 1, high, prev);
	}

	return NULL;
}
/* Calls the binary function for our route table and the given ip, in order to find the entry*/
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	return binary(ip_dest, 0, rtable_len - 1, NULL);
}
/* Iterates through the ar table in order to find the element for the given ip*/
struct arp_entry *get_arp_entry(uint32_t given_ip)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		if (artable[i].ip == given_ip)
		{
			return &artable[i];
		}
	}

	return NULL;
}
/* Creates an arp request*/
void generate_ARP_request(struct route_table_entry *next)
{
	struct ether_header new_eth;
	struct arp_header new_arp;
	char *buff = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	uint8_t broadcast[6];
	for (int i = 0; i < 6; i++)
		broadcast[i] = 255;
	// New header created with current interface's mac as sender and broadcast as destination, type is set to ARP
	new_eth.ether_type = htons(ETHERNET_ARP);
	get_interface_mac(next->interface, new_eth.ether_shost);
	memcpy(new_eth.ether_dhost, broadcast, 6 * sizeof(uint8_t));
	// Htype is set to mac and it's size, ptype is set to IPV4 and it's size
	new_arp.htype = htons(1);
	new_arp.hlen = 6 * sizeof(uint8_t);

	new_arp.ptype = htons(ETHERNET_IPV4);
	new_arp.plen = sizeof(uint32_t);

	new_arp.op = htons(1);
	// Arp sender set to current interface's mac and ip
	get_interface_mac(next->interface, new_arp.sha);
	new_arp.spa = inet_addr(get_interface_ip(next->interface));
	// Destination mac set to 0 (to be determined via arp reply), ip set to next_hop( of the best route found in rtable)
	for (int i = 0; i < 6; i++)
		new_arp.tha[i] = 0;

	memcpy(&new_arp.tpa, &next->next_hop, sizeof(uint32_t));
	// Elements added to buff, which is sent to the next interface
	memcpy(buff, &new_eth, sizeof(struct ether_header));
	memcpy(buff + sizeof(struct ether_header), &new_arp, sizeof(struct arp_header));
	send_to_link(next->interface, buff, sizeof(struct ether_header) + sizeof(struct arp_header));
}
// Checks if received ARP is reply or request and does what is neccesary for each
void parseARP(char *buf, int interface, int len)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;

	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	queue still_waiting = queue_create();
	// If the ARP is a request:
	if (arp_hdr->op == htons(1))
	{	
		if(inet_addr(get_interface_ip(interface)) != arp_hdr->tpa){
			return;
		}
		// Places sender's ip and mac in the destination one's
		memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(uint8_t) * 6);
		memcpy(&arp_hdr->tpa, &arp_hdr->spa, sizeof(uint32_t));
		// Sender become current interface's ip and mac
		arp_hdr->spa = inet_addr(get_interface_ip(interface));
		get_interface_mac(interface, arp_hdr->sha);
		// Reset types in order to not have any hton / ntoh data transmission problems
		arp_hdr->htype = htons(1);
		arp_hdr->hlen = 6 * sizeof(uint8_t);

		arp_hdr->ptype = htons(ETHERNET_IPV4);
		arp_hdr->plen = sizeof(uint32_t);

		arp_hdr->op = htons(2);

		eth_hdr->ether_type = htons(ETHERNET_ARP);
		// Destination is set as sender ip, sender is set as current's interfaces mac
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
		get_interface_mac(interface, eth_hdr->ether_shost);

		send_to_link(interface, buf, len);
		return;
	}
	else
	{ // Add's the mac received through the reply into the arptable, so we dont have to request it everytime
		struct arp_entry add;
		memcpy(&add.ip, &arp_hdr->spa, sizeof(uint32_t));
		memcpy(add.mac, arp_hdr->sha, sizeof(uint8_t) * 6);
		artable[arp_table_len] = add;
		arp_table_len++;

		while (!queue_empty(waiting))
		{
			// Extracts each arp_data struct (contains a IPV4 buffer and it's length)
			struct arp_data *next = (struct arp_data *)queue_deq(waiting);
			struct iphdr *new_iphdr = (struct iphdr *)(next->buff + sizeof(struct ether_header));
			struct route_table_entry *best = get_best_route(new_iphdr->daddr);
			// If the next_hop now has an arp entry it's exetracted from the queueu and sent to it's destonation
			// whose mac is know known
			if (get_arp_entry(best->next_hop) != NULL)
			{
				struct ether_header *new_hdr = (struct ether_header *)next->buff;
				struct arp_entry *entry = get_arp_entry(best->next_hop);
				memcpy(new_hdr->ether_dhost, entry->mac, sizeof(uint8_t) * 6);
				get_interface_mac(best->interface, new_hdr->ether_shost);
				send_to_link(best->interface, next->buff, next->length);
			}
			else
			{
				// Puts each element into the  still_waiting queue, which was not resent
				queue_enq(still_waiting, next);
			}
		}
		while (!queue_empty(still_waiting))
		{ // Readds all the elements that have not been sent to the waiting queue
			queue_enq(waiting, queue_deq(still_waiting));
		}
	}
};
// Compares 2 macs
int check_macs(uint8_t first[6], uint8_t second[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (first[i] != second[i])
		{
			return 0;
		}
	}

	return 1;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	//  Do not modify this line
	init(argc - 2, argv + 2);
	// Queue created for proccesses that are waiting for an arp reply
	waiting = queue_create();
	// Rtable alloced and read, used for finding the best route to our destination
	rtable = NULL;
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	rtable_len = read_rtable(argv[1], rtable);
	// Sorted for binary search
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comparator);

	// Ar table alloced and it's size set to 0 to add elements via ARP later
	artable = NULL;
	artable = malloc(sizeof(struct arp_entry) * 80000);
	arp_table_len = 0;

	while (1)
	{

		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		uint8_t copy[6];
		get_interface_mac(interface, copy);
		uint8_t broadcast[6];
		for (int i = 0; i < 6; i++)
			broadcast[i] = 255;
		// If the received packet is not for the host or is a broadcast it is dropped
		if (!check_macs(copy, eth_hdr->ether_dhost) && !check_macs(broadcast, eth_hdr->ether_dhost))
		{
			continue;
		}
		// If the package is an ARP it is send throught the ParseArp function explained further up
		if (htons(eth_hdr->ether_type) == ETHERNET_ARP)
		{
			parseARP(buf, interface, len);
			continue;
		}
		// If not IPV4 packet is dropped, as we already checked for ARP
		if (htons(eth_hdr->ether_type) != ETHERNET_IPV4)
		{
			continue;
		}

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		uint16_t old_check = ntohs(ip_hdr->check);
		ip_hdr->check = 0x0000;
		// Recalculates the checksum after setting it to 0 and if it's diffrent
		// from the old one it means the old one was sent wrong and packet is
		// dropped
		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != old_check)
		{
			continue;
		}
		// If it has no time to live left packet is dropped
		if (ip_hdr->ttl <= 1)
		{
			continue;
		}

		// Decreases time to live and reacalculates the chechsum
		ip_hdr->ttl--;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		// Uses the get_best_route function to find the best route to our destination
		// in the route table
		struct route_table_entry *best = malloc(sizeof(struct route_table_entry));
		best = get_best_route(ip_hdr->daddr);

		// If there is no route the package is dropped
		if (best == NULL)
		{
			continue;
		}
		// Finds mac of the next_hop for our route
		struct arp_entry *next = get_arp_entry(best->next_hop);
		// If it does not have one it send and ARP request
		if (next == NULL)
		{
			// Creates a arp_data struct (a buffer and it's length)
			// and adds it the queue
			struct arp_data new;
			new.buff = malloc(len);
			memcpy(new.buff, buf, len);
			new.length = len;
			queue_enq(waiting, &new);
			// Calls the fucntion to generate an ARP request
			generate_ARP_request(best);
			continue;
		}
		// Sets sender to best interface's found mac
		// And sets destination to the mac of the next_hop towards our
		// destination
		get_interface_mac(best->interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, next->mac, sizeof(uint8_t) * 6);
		// Sends the packet towards our destination
		send_to_link(best->interface, buf, len);
		continue;
	}
}
