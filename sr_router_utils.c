

//returns gateway
bool longest_prefix_match(struct sr_rt* routing_table, uint32_t lookup, struct sr_rt **best_match) 
{
	/* Assume entries in the lookup table are not already masked */
	bool found = false;
	uint32_t max_prefix = 0;
	for(struct sr_rt* cur = routing_table; cur != 0; cur = cur->next) {
		uint32_t mask = (uint32_t) cur->mask.s_addr;
		uint32_t cur_addr_masked = ((uint32_t)cur->dest.s_addr & mask);
		uint32_t lookup_masked = (lookup & mask);
		if ((lookup_masked == cur_addr_masked) && 
		   (!found || (mask > max_prefix))) {
			found = true;
			max_prefix = mask;
			*best_match = cur;
		}
	}
	
	return found;
}


time_t current_time() 
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC,&ts);
	return ts.tv_sec;
}

uint8_t * extract_frame_payload(sr_ethernet_hdr_t *frame,unsigned int len,unsigned int *len_payload)
{
	if (len_payload != 0) {
		*len_payload = len - sizeof(sr_ethernet_hdr_t);
	}
	return ((uint8_t *)frame + sizeof(sr_ethernet_hdr_t));
}

bool ether_addr_equals(uint8_t *ether_addr1, uint8_t *ether_addr2)
{
  	for (int i=0; i < ETHER_ADDR_LEN; i++) {
    	if (ether_addr1[i] != ether_addr2[i])
    		return false;
  	}
  	return true;
}

/*
bool match_interface_ipaddr(struct sr_instance *sr,uint32_t ipaddr,const char * interface) 
{
	sr_if_t *ifptr = sr_get_interface(sr,interface);
	
	//check if interface exists
	if (ifptr == 0)
		return false;
		
	return (ipaddr == ifptr->ip);
}
*/

bool match_interface_etheraddr(struct sr_instance *sr,uint8_t *ethaddr,const char * interface) 
{
	sr_if_t *ifptr = sr_get_interface(sr,interface);
	
	//check if interface exists
	if (ifptr == 0)
		return false;
		
	return ether_addr_equals(ifptr->addr,ethaddr);

}

bool is_broadcast_frame(uint8_t *addr)
{
	for (int i=0; i < ETHER_ADDR_LEN; i++) {
    	if (addr[i] != 0xff)
    		return false;
  	}
  	return true;
}

bool addressed_to_instance(struct sr_instance *sr,sr_ethernet_hdr_t *frame,const char *interface, bool broadcast_ok)
{
	if (broadcast_ok) {
		if (is_broadcast_frame(frame->ether_dhost))
			return true;
	}
		
	return match_interface_etheraddr(sr,frame->ether_dhost,interface);
}

//returns number of msec in current clock
uint16_t generate_id()
{
	struct timespec ts;
	clock_gettime(1,&ts);
	return (uint16_t) ts.tv_nsec;
}

bool my_ip_address(struct sr_instance *sr,uint32_t ipaddr, sr_if_t **iface)
{

	for (sr_if_t *inf = sr->if_list;inf != 0; inf=inf->next) {
		if (inf->ip == ipaddr) {
			//optional return interface found
			if (iface != 0) {
				*iface = inf;
			}
			return true;
		}
	}
	return false;
}





















