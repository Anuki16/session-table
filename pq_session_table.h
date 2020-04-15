/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_session_table.h
 * Author: paraqum
 *
 * Created on April 7, 2020, 10:05 PM
 */

#ifndef PQ_SESSION_TABLE_H
#define PQ_SESSION_TABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* for pcap */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <time.h>   /*for timing*/
#include <unordered_map>    /*hash table*/
#include "pq_queue.h"

/*struct for hashtable value*/
struct hashValue{
    u_int32_t upload;
    u_int32_t download;
    u_int sessionNo;
    time_t lastTime;
    struct in_addr sourceIP;
    struct in_addr destIP;
};

/*hash table*/
std::unordered_map<u_int64_t,struct hashValue> hashtable;

/*timer to check for timeout*/
time_t last_check;

/*compare in_addr structures to see if IP is the same*/
int compareIP(struct in_addr ip1,struct in_addr ip2){
    return ip1.s_addr==ip2.s_addr;
}

u_int64_t make_hash(pq_flow_element packet){
    return (packet.sip.s_addr)^(packet.dip.s_addr)^(packet.sport)^(packet.dport)^(packet.prot);
}



/*update hash table
 return session number if new key
 return 0 if existing key*/
u_int update(pq_flow_element packet,in_addr machine_ip){
    static u_int session=0;
    u_int64_t hashkey=make_hash(packet);
    if(hashtable.find(hashkey)==hashtable.end()){
        session++;
        struct hashValue value;
        
        if (compareIP(packet.sip,machine_ip)){
            value.sourceIP=machine_ip;
            value.destIP=packet.dip;
            
        }
        else if (compareIP(packet.dip,machine_ip)){
            value.sourceIP=machine_ip;
            value.destIP=packet.sip;
        }
        else{
            value.sourceIP=packet.sip;
            value.destIP=packet.dip;
        }
        value.upload=value.download=0;
        
        if (compareIP(value.sourceIP,packet.sip)){
            value.upload+=packet.data;
            
        }else{
            value.download+=packet.data;
            
        }
        
        value.sessionNo=session;
        time(&value.lastTime);
        hashtable[hashkey]=value;
        
        
        return session;
    }
    
    time(&hashtable[hashkey].lastTime);
    
    if (compareIP(hashtable[hashkey].sourceIP,packet.sip)){
            hashtable[hashkey].upload+=packet.data;
            
        }else{
            hashtable[hashkey].download+=packet.data;
        }
    return 0;
}

/*Check if sessions ended*/
void endSessions(FILE *fPointer,const int TIMEOUT){
    
    time_t now;
    time(&now);
    std::unordered_map<u_int64_t,struct hashValue>::iterator iter=hashtable.begin();
    
    while(iter!=hashtable.end()){
        struct hashValue value=iter->second;
        if((now-value.lastTime)>=TIMEOUT){
            fprintf(fPointer,"Session %d\n",value.sessionNo);
            fprintf(fPointer,"upload data (%s) %u bytes, ",inet_ntoa(value.sourceIP),value.upload);
            fprintf(fPointer,"download data (%s) %u bytes\n\n",inet_ntoa(value.destIP),value.download);
            iter=hashtable.erase(iter);
        }else{
            iter++;
        }
    }
}

void print_table(pq_flow_element packet,u_int session){
    printf("Session %u\t%s\t",session,inet_ntoa(packet.sip));
    printf("%s\t",inet_ntoa(packet.dip));
    if (packet.prot==IPPROTO_TCP){
        printf("TCP\t");
    }else if (packet.prot==IPPROTO_UDP){
        printf("UDP\t");
    }

    printf("%u\t",ntohs(packet.sport));
    printf("%u\t\n",ntohs(packet.dport));      
}


#endif /* PQ_SESSION_TABLE_H */

