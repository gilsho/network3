/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdbool.h>
#include "sr_router_utils.c"
 

 #define TTL_VALUE 128
 #define CHK_SUM_VALUE 0xffff
 
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */


/*---------------------------------------------------------------------
 * Method: wrap_frame

 * Scope:  Global
 *
 * Takes a payload and its type, wraps it into an appropriate ethernet
 * header and sends it out on the appropriate interface
 *
 *---------------------------------------------------------------------*/

void wrap_frame(struct sr_instance *sr,sr_if_t* interface, uint8_t *payload, unsigned int pyldlen,uint8_t * deth,uint16_t ethtype)
{
	//wrap in ethernet header
	unsigned int frlen = sizeof(sr_ethernet_hdr_t) + pyldlen;
	sr_ethernet_hdr_t *frame = malloc(frlen); 
	
	memcpy(&frame->ether_shost,interface->addr,ETHER_ADDR_LEN);
	memcpy(&frame->ether_dhost,deth,ETHER_ADDR_LEN);
	frame->ether_type = htons(ethtype);
	
	uint8_t *buf = (uint8_t *)frame;
	unsigned int offset = sizeof(sr_ethernet_hdr_t);
	memcpy(buf+offset,payload,pyldlen);
	
	Debug("----- Sending frame ---------");
	DebugFrame(frame,frlen);
	sr_send_packet(sr,(uint8_t *) frame,frlen,interface->name);
							   
	free(frame);
	
}

/*---------------------------------------------------------------------
 * Method: send_arp_request

 * Scope:  Global
 *
 * Constructs an arp reply packet by filling in the instance's ethernet
 * address and sends it through the given interface
 *
 *---------------------------------------------------------------------*/

void set_ether_addr_broadcast(uint8_t * ethr_addr) 
{
	for (int i=0;i<ETHER_ADDR_LEN;i++){
		ethr_addr[i] = 0xff;
	}
}

void send_arp_request(struct sr_instance *sr, const char *ifname,uint32_t tip) 
{
	//locate ip address and ethernet address for interface to populate the sender fields
	sr_if_t * interface = sr_get_interface(sr,ifname);
	uint32_t sip = interface->ip;
	
	sr_arp_hdr_t arphdr;

	arphdr.ar_hrd = htons(arp_hrd_ethernet);	//hardware type
	arphdr.ar_pro = htons(arp_protocol_ipv4);  //protocol type				
	arphdr.ar_hln = arp_protlen_eth; 			//hardware address length
	arphdr.ar_pln = arp_protlen_ipv4;			//protocol address length
	arphdr.ar_op = htons(arp_op_request);		//op code
	
	//source addresses
	memcpy(arphdr.ar_sha,interface->addr,arp_protlen_eth);
	arphdr.ar_sip = sip;
	
	//target addresses
	uint8_t broadcast_addr[ETHER_ADDR_LEN];
	set_ether_addr_broadcast(broadcast_addr);
	memcpy(arphdr.ar_tha,broadcast_addr,arp_protlen_eth);
	arphdr.ar_tip = tip;
	
	wrap_frame(sr,interface,(uint8_t *)&arphdr,sizeof(sr_arp_hdr_t),broadcast_addr,ethertype_arp);

}

/*---------------------------------------------------------------------
 * Method: send_arp_reply

 * Scope:  Global
 *
 * Constructs an arp reply packet by filling in the instance's ethernet
 * address and sends it through the given interface
 *
 *---------------------------------------------------------------------*/

void send_arp_reply(struct sr_instance *sr, sr_if_t *iface,uint8_t *teth,uint32_t tip) 
{
	//locate ip address and ethernet address for interface to populate the sender fields
	uint32_t sip = iface->ip;
	
	sr_arp_hdr_t arphdr;

	arphdr.ar_hrd = htons(arp_hrd_ethernet);	//hardware type
	arphdr.ar_pro = htons(arp_protocol_ipv4);  //protocol type				
	arphdr.ar_hln = arp_protlen_eth; 			//hardware address length
	arphdr.ar_pln = arp_protlen_ipv4;			//protocol address length
	arphdr.ar_op = htons(arp_op_reply);		//op code
	
	//source addresses
	memcpy(arphdr.ar_sha,iface->addr,arp_protlen_eth);
	arphdr.ar_sip = sip;
	
	//target addresses
	memcpy(arphdr.ar_tha,teth,arp_protlen_eth);
	arphdr.ar_tip = tip;
	
	wrap_frame(sr,iface,(uint8_t *)&arphdr,sizeof(sr_arp_hdr_t),teth,ethertype_arp);

}

/*---------------------------------------------------------------------
 * Method: valid_arp_packet

 * Scope:  Global
 *
 * Checks to ensure a received arp packet is valid. currently this means
 * chacking that it exceeds a minimum length
 *
 *---------------------------------------------------------------------*/

bool valid_arp_packet(unsigned int arplen)
{
	return (arplen >= sizeof(sr_arp_hdr_t));
}

/*---------------------------------------------------------------------
 * Method: handle_ARP

 * Scope:  Global
 *
 * handles an incoming arp packet
 *
 *---------------------------------------------------------------------*/

void process_pending_packets(struct sr_instance *sr,sr_arpreq_t *arpreq);

void handle_ARP(struct sr_instance* sr, sr_ethernet_hdr_t *frame, unsigned int len, const char *ifname)
{
	
	unsigned int arplen = 0;
	sr_arp_hdr_t * arphdr = (sr_arp_hdr_t *) extract_frame_payload(frame,len,&arplen);	
	
	if (!valid_arp_packet(arplen)) {
		Debug("Dropping frame. Invalid ARP header.\n");
		return;
	}
	
	//check if ip target matches the interface through which frame was received
	uint32_t tip = arphdr->ar_tip;
	sr_if_t *iface = sr_get_interface(sr,ifname);
	if ((iface != 0) && (iface->ip != tip)) {
		Debug("Target ip in packet [%d] does not match interface [%s]",tip,iface->name);
		return;
	}
	
	
	//insert sender mac and ip into cache regardless of type of arp message
	uint8_t *seth = arphdr->ar_sha;
    uint32_t sip = arphdr->ar_sip;	//remain in network byte order
	struct sr_arpreq * arpreq = sr_arpcache_insert(&sr->cache,seth,sip);
	
	//deal with packets waiting for this ip address
	if (arpreq != 0) {
		process_pending_packets(sr,arpreq);
	}
		
	//issue reply if this is a request
	if (arphdr->ar_op == htons(arp_op_request)) {
		send_arp_reply(sr, iface,seth,sip);
	}
	
}

void process_pending_packets(struct sr_instance *sr, sr_arpreq_t *arpreq) 
{
	sr_arpentry_t * arpentry = sr_arpcache_lookup(&sr->cache, arpreq->ip);
	assert(arpentry != 0);	//this function should be called once arp reply has
							//been received and inserted into cache

	for (sr_packet_t *pkt = arpreq->packets; pkt != 0; pkt = pkt->next) {
		wrap_frame(sr,sr_get_interface(sr,arpreq->iface),pkt->buf,pkt->len,arpentry->mac,ethertype_ip);
	}
	sr_arpreq_destroy(&sr->cache,arpreq);
}

void reject_pending_packets(struct sr_instance *sr,sr_arpreq_t *arpreq)
{
	sr_if_t *iface = sr_get_interface(sr,arpreq->iface);
	for (sr_packet_t *pkt = arpreq->packets; pkt != 0; pkt = pkt->next) {
		send_ICMP_host_unreachable(sr,(sr_ip_hdr_t *)pkt->buf,iface);
	}
	sr_arpreq_destroy(&sr->cache,arpreq);
}

/*---------------------------------------------------------------------
 * Method: valid_ip_packet

 * Scope:  Global
 *
 * checks to see if received ip packet is valid. checks included length,
 * and checksum
 *
 * TODO: add a check for header length
 *
 *---------------------------------------------------------------------*/

bool valid_ip_packet(sr_ip_hdr_t *iphdr,unsigned int ip_len) 
{
	//Debug("IP Length in packet: [%d], IP Length Read [%d]\n",ntohs(iphdr->ip_len),ip_len);
	if(ntohs(iphdr->ip_len) > ip_len)
		return false;

	//Debug("stored sum: [%d], computed sum: [%d]",stored_sum,computed_sum);
	if (cksum(iphdr,sizeof(sr_ip_hdr_t)) != CHK_SUM_VALUE)
		return false;
		
	return true;
}

/*---------------------------------------------------------------------
 * Method: route_ip_packet

 * Scope:  Global
 *
 * given a fully constructed, ip packet, looks up the appropriate interface
 * in the routing tabke, and then hands it off to wrap_frame method
 * to wrap hte packet inside an ethernet frame and send it
 *
 *---------------------------------------------------------------------*/

void route_ip_packet(struct sr_instance *sr,sr_ip_hdr_t *iphdr,sr_if_t *in_iface)
{
	//last prefix match and find matching prefix
	//if not found - send ICMP host unreachable
	//lookup arp cache. if not there - enqueue and issue arp request
	//print_hdr_ip((uint8_t *) iphdr);
	//print_hdr_icmp(((uint8_t *)iphdr) + sizeof(sr_ip_hdr_t));

	struct sr_rt *rt_entry;
	bool found = longest_prefix_match(sr->routing_table,iphdr->ip_dst,&rt_entry);
	if (!found) {
		send_ICMP_host_unreachable(sr,iphdr,in_iface);	
		return;
	}

	sr_arpentry_t * arpentry = 0;

	arpentry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

	if (arpentry == 0) {
	
		sr_arpreq_t * arpreq = sr_arpcache_queuereq(&sr->cache,rt_entry->gw.s_addr,(uint8_t *)iphdr,ntohs(iphdr->ip_len),
														  rt_entry->interface);
		handle_arpreq(sr,arpreq);
		return;
	} 

	sr_if_t* out_iface = sr_get_interface(sr,rt_entry->interface);
	assert(out_iface != 0);	//Bad routing table otherwise

	wrap_frame(sr,out_iface,(uint8_t *)iphdr,ntohs(iphdr->ip_len),arpentry->mac,ethertype_ip);

	free(arpentry);


}


/*---------------------------------------------------------------------
 * Method: wrap_ip_packet

 * Scope:  Global
 *
 * given a fully constructed transport/application segment, wraps it
 * inside an ip header and sends it to wrap_frame to sends it to
 * route_ip_packet to deliver to its destination
 *
 *---------------------------------------------------------------------*/

void wrap_ip_packet(struct sr_instance *sr,uint8_t *payload, unsigned int pyldlen,
							   uint32_t sip,uint32_t dip,uint8_t protocol,sr_if_t *iface)
{
	if (my_ip_address(sr,dip,0)) {
		Debug("--Pending packet addressed to self. cancelling transmission\n");
		return;
	}

	unsigned int pktlen = sizeof(sr_ip_hdr_t) + pyldlen;
	sr_ip_hdr_t *iphdr = malloc(pktlen);

	iphdr->ip_hl = (unsigned int) (sizeof(sr_ip_hdr_t)/4); 
	iphdr->ip_v = ip_version_4;
	iphdr->ip_tos = 0;							//unsupported
	iphdr->ip_len = htons(pktlen); 
	iphdr->ip_id = htons(generate_id()); 		//random id
	iphdr->ip_off = 0;							//unsupported
	iphdr->ip_ttl = TTL_VALUE;
	iphdr->ip_p = protocol; 
	iphdr->ip_src = sip;
	iphdr->ip_dst = dip;

	//copy payload
	uint8_t *buf = (uint8_t *)iphdr;
	unsigned int offset = sizeof(sr_ip_hdr_t);
	memcpy(buf+offset,payload,pyldlen);

	//compute checksum
	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum(iphdr,pktlen);

	route_ip_packet(sr,iphdr,iface);

	free(iphdr);

}

void send_ICMP_ttl_exceeded(struct sr_instance *sr, sr_ip_hdr_t *recv_iphdr,sr_if_t *iface)
{
  	sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) malloc(ICMP_PACKET_SIZE);
  	memset(icmphdr,0,ICMP_PACKET_SIZE);

	icmphdr->icmp_type = icmp_type_ttl_expired;
	icmphdr->icmp_code = icmp_code_ttl_expired_in_transit;
	
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;

	wrap_ip_packet(sr,(uint8_t *)icmphdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmphdr);
}

void send_ICMP_host_unreachable(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr, sr_if_t *iface)
{
	sr_icmp_t3_hdr_t *icmp3hdr = (sr_icmp_t3_hdr_t *) malloc(ICMP_PACKET_SIZE);
	memset(icmp3hdr,0,ICMP_PACKET_SIZE);

	memcpy(&icmp3hdr->data,recv_iphdr,ICMP_DATA_SIZE);

	icmp3hdr->icmp_type = icmp_type_dst_unrch;
	icmp3hdr->icmp_code = icmp_code_dst_unrch_host;

	icmp3hdr->icmp_sum = 0;
	icmp3hdr->icmp_sum = cksum(icmp3hdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;
	
	wrap_ip_packet(sr,(uint8_t *)icmp3hdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmp3hdr);
}

void send_ICMP_port_unreachable(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr,sr_if_t *iface)
{
	sr_icmp_t3_hdr_t *icmp3hdr = (sr_icmp_t3_hdr_t *) malloc(ICMP_PACKET_SIZE);
	memset(icmp3hdr,0,ICMP_PACKET_SIZE);

	memcpy(&icmp3hdr->data,recv_iphdr,ICMP_DATA_SIZE);

	icmp3hdr->icmp_type = icmp_type_dst_unrch;
	icmp3hdr->icmp_code = icmp_code_dst_unrch_port;

	icmp3hdr->icmp_sum = 0;
	icmp3hdr->icmp_sum = cksum(icmp3hdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;
	
	wrap_ip_packet(sr,(uint8_t *)icmp3hdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmp3hdr);
}

uint8_t * extract_ip_payload(sr_ip_hdr_t *iphdr,unsigned int len,unsigned int *len_payload)
{
	if (len_payload != 0) {
		*len_payload = len - sizeof(sr_ip_hdr_t);
	}
	return ((uint8_t *)iphdr+ sizeof(sr_ip_hdr_t));
}

void send_ICMP_echoreply(struct sr_instance *sr,sr_ip_hdr_t *recv_iphdr,sr_if_t *iface)
{

	unsigned int icmp_len = 0;

	sr_icmp_hdr_t *recv_icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(recv_iphdr,ntohs(recv_iphdr->ip_len),&icmp_len);
	sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) malloc(ICMP_PACKET_SIZE);

	memcpy(icmphdr,recv_icmphdr,icmp_len);
	icmphdr->icmp_type = icmp_type_echoreply;
	icmphdr->icmp_code = 0x00;
	icmphdr->icmp_sum = 0;
	icmphdr->icmp_sum = cksum(icmphdr,ICMP_PACKET_SIZE);

	uint32_t sip = iface->ip;
	uint32_t dip = recv_iphdr->ip_src;
	
	wrap_ip_packet(sr,(uint8_t *)icmphdr,ICMP_PACKET_SIZE,sip,dip,ip_protocol_icmp,iface);

	free(icmphdr);
}


bool valid_icmp_echoreq(sr_icmp_hdr_t *icmphdr,unsigned int icmplen)
{
	if  (icmplen < ICMP_PACKET_SIZE)
		return false;
		
	if (icmphdr->icmp_type != icmp_type_echoreq)
		return false;
	
	if (cksum(icmphdr,ICMP_PACKET_SIZE) != CHK_SUM_VALUE)
		return false;
		
	return true;
}

void process_ip_payload(struct sr_instance *sr,sr_ip_hdr_t *iphdr,unsigned int iplen,sr_if_t *iface) 
{
	if (iphdr->ip_p != ip_protocol_icmp) {
		Debug("--Non-ICMP packet addressed to router. invalid IP header.\n");
		send_ICMP_port_unreachable(sr,iphdr,iface);
		return;
	} 
	
	unsigned int icmplen=0;
	sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) extract_ip_payload(iphdr,iplen,&icmplen);
	
	if (!valid_icmp_echoreq(icmphdr,icmplen)) {
		Debug("--Invalid ICMP echo request. dropping packet\n");
		return;
	}
	
	send_ICMP_echoreply(sr,iphdr,iface);
	
}

void handle_IP(struct sr_instance* sr, sr_ethernet_hdr_t *frame, unsigned int len, const char * ifname)
{
	unsigned int iplen = 0;
	sr_ip_hdr_t * iphdr = (sr_ip_hdr_t *) extract_frame_payload(frame,len,&iplen);
	
	if (!valid_ip_packet(iphdr,iplen)) {
		Debug("--Dropping frame. invalid IP header.\n");
		return;
	}

	sr_if_t *iface; 
	iface = sr_get_interface(sr,ifname); 

	if (iphdr->ip_ttl <= 0) {
		Debug("--TTL exceeded.\n");
		send_ICMP_ttl_exceeded(sr,iphdr,iface);
		return;
	}
	
	if (my_ip_address(sr,iphdr->ip_dst,&iface))
	{
		//IP packet destined to me directly
		Debug("--Packet addressed to router");
		process_ip_payload(sr,iphdr,len,iface);
		return;
	} 

	//update time to live
	iphdr->ip_ttl--;
	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));

	
	route_ip_packet(sr,iphdr,iface);	

}



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
  	assert(sr);
  	assert(packet);
  	assert(interface);

  	Debug("*** -> Received packet of length [%d] in interface [%s] \n",len,interface);
  	
  	//log incoming frame
	DebugFrame(packet,len);


  	/* fill in code here */
  	
  	sr_ethernet_hdr_t *frame = (sr_ethernet_hdr_t *) packet;
  	
  	uint16_t ethtype = ethertype(packet);
  	
	if (ethtype == ethertype_ip) {
		Debug("--- IP packet detected\n");
		if (addressed_to_instance(sr,frame,interface,false)) {
			handle_IP(sr,frame,len,interface);
		} else {
			Debug("Frame dropped. addressed to MAC address:[");
			DebugMAC(frame->ether_dhost);
			Debug("]\n");
		}
		
	} else if (ethtype == ethertype_arp) {
		Debug("--- ARP packet detected\n");
		if (addressed_to_instance(sr,frame,interface,true)) {
			handle_ARP(sr,frame,len,interface);
		} else {
			Debug("Frame dropped. addressed to MAC address:[");
			DebugMAC(frame->ether_dhost);
			Debug("]\n");
		}
		
	} else {
		Debug("-- Frame dropped. Unknown frame type: [%d]\n",ethtype);
	}
	  	  
}/* end sr_ForwardPacket */
















