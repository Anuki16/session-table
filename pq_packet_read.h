/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_packet_read.h
 * Author: paraqum
 *
 * Created on April 7, 2020, 10:03 PM
 */

#ifndef PQ_PACKET_READ_H
#define PQ_PACKET_READ_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* for pcap */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 

/*open device and read packets
 * count : no. of packets to read (-1 if infinite loop)
 * callback : callback function for pcap_loop
 * wait_time : time to wait before reading packets
 return 2 if error*/
int read_packets(int count,pcap_handler callback,int wait_time){
    
    char *dev;
    char *net;
    char *mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    int ret;
    struct in_addr addr;
    pcap_t *handle;
    
    /*look up device*/
    dev=pcap_lookupdev(errbuf);
    if (dev==NULL){
        fprintf(stderr, "Couldn't find default device %s: %s\n", errbuf);
        return(2);
    }
           
    printf("Device : %s\n",dev);
    
    /*look up network address and subnet mask*/
    ret=pcap_lookupnet(dev,&netp,&maskp,errbuf);
    if (ret==-1){
        fprintf(stderr, "%s\n",errbuf);
        return(2);
    }
    addr.s_addr=netp;
    net=inet_ntoa(addr);
    if( net==NULL){
        perror("inet_ntoa");
        return(2);
        
    }
    printf("Net : %s\n",net);
    
    addr.s_addr=maskp;
    mask=inet_ntoa(addr);
    if(mask==NULL){
        perror("inet_ntoa");
        return(2);
    }
    printf("Mask : %s\n\n",mask);
    
    handle = pcap_open_live(dev, BUFSIZ, 1, wait_time, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}
    
    pcap_loop(handle,count,callback,NULL);
    pcap_close(handle);
    return 0;
}





#endif /* PQ_PACKET_READ_H */

