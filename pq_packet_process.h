/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_packet_process.h
 * Author: paraqum
 *
 * Created on April 7, 2020, 10:05 PM
 */

#ifndef PQ_PACKET_PROCESS_H
#define PQ_PACKET_PROCESS_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* for pcap */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include "pq_header_structs.h"
#include "pq_queue.h"

#define SIZE_ETHERNET 14

/*find packet details and store it in packet_info
 return 0 if TCP or UDP, else 1*/
int process_packets(const struct pcap_pkthdr* header,const u_char *packet,pq_flow_element *packet_info){
    
    /*packet header pointers*/
    const struct ether_header* ethernet;
    const struct sniff_ip* ip;
    
    /*header sizes*/
    int size_ip;
    
    /*typecast*/
    ethernet=(struct ether_header*)(packet);
    ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
    
    size_ip = IP_HL(ip)*4;
    if (size_ip<20){
        
        return 1;
    }
    
    /*fill in flow element*/
    
    packet_info->sip=ip->ip_src;
    packet_info->dip=ip->ip_dst;
    packet_info->data=header->len;
    packet_info->prot=ip->ip_p;
    
    /*check protocol*/
    if (ip->ip_p==IPPROTO_TCP){
        const struct sniff_tcp* tcp;
        tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
        packet_info->sport=tcp->th_sport;
        packet_info->dport=tcp->th_dport;
    }else if (ip->ip_p==IPPROTO_UDP){
        const struct sniff_udp* udp;
        udp=udp=(struct sniff_udp *)(packet+SIZE_ETHERNET+size_ip);
        packet_info->sport=udp->sport;
        packet_info->dport=udp->dport;
    }else{
        return 1;
    }
    return 0;
    
    
}



#endif /* PQ_PACKET_PROCESS_H */

