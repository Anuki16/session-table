/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.cpp
 * Author: paraqum
 *
 * Created on April 7, 2020, 9:56 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* for pcap */
#include <time.h>
#include "pq_packet_read.h"
#include "pq_packet_process.h"
#include "pq_session_table.h"
#include "pq_queue.h"
#include <pthread.h>
#include <signal.h>

using namespace std;

/*
 * 
 */

const int TIMEOUT=60*3;
int packet_count=-1;
int wait_time=1000;

/*open file to record ended sessions*/
FILE* fPointer;


struct in_addr machine_ip;



/*flag to end session_table loop*/
int ended=0;

void closeFile(int signum){
    fclose(fPointer);
    ended=1;
    
    exit(signum);
    
    
}

/*pcap_loop callback*/
void gotpacket(u_char *args,const struct pcap_pkthdr* header,const u_char *packet){
    pq_flow_element packet_info;
    int retval=process_packets(header,packet,&packet_info);
    if (retval!=0){
        return;
    }
    pq_queue_push(packet_info);
}

void *get_packets(void *arg){
    
    read_packets(packet_count,gotpacket,wait_time);
    ended=1;
    
}

void *session_table(void *arg){
    while(1){
        if (pq_flow_array_wp!=pq_flow_array_rp){
            pq_flow_element packet=pq_queue_pull();
            u_int session=update(packet,machine_ip);
            if (session!=0){
                print_table(packet,session);
            }
        }
        if (ended && pq_flow_array_wp==pq_flow_array_rp){
            break;
        }
        time_t now;
        time(&now);
        if ((now-last_check)>=TIMEOUT){
            endSessions(fPointer,TIMEOUT);
            last_check=now;
        }
    }
}


int main(int argc, char** argv) {
    
    pthread_t read_id;
    pthread_t table_id;
    
    time(&last_check);
    
    fPointer=fopen("sessionrecords.txt","w");
    
    inet_aton("192.168.1.112",&machine_ip);
    
    signal(SIGINT,closeFile);
    
    pthread_create(&read_id,NULL,get_packets,NULL);
    pthread_create(&table_id,NULL,session_table,NULL);
    
    pthread_join(read_id,NULL);
    pthread_join(table_id,NULL);

    return 0;
}

