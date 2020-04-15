/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pq_queue.h
 * Author: hasith@paraqum.com
 * Description : Queue Implimentation  
 * Created on March 28, 2020, 2:26 PM
 */

#ifndef PQ_QUEUE_H
#define PQ_QUEUE_H

#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include "pq_print_color_defs.h"

typedef struct {
    u_char prot;    
    struct in_addr sip;     
    struct in_addr dip;
    u_short sport;
    u_short dport;
    uint32_t data;
} pq_flow_element;


pq_flow_element pq_flow_array[UINT16_MAX] = {0};
uint16_t pq_flow_array_wp = 0;
uint16_t pq_flow_array_rp = 0;

void pq_queue_push(pq_flow_element ele) {
    pq_flow_array[pq_flow_array_wp] = ele;
    pq_flow_array_wp++;
    if (pq_flow_array_wp == pq_flow_array_rp) {
        printf(KRED "PQ QUEUE :: OVERFLOW" KRESET "\n");
    }
}

pq_flow_element pq_queue_pull() {
    return pq_flow_array[pq_flow_array_rp++];
}

#endif /* PQ_QUEUE_H */

