/*
 * Copyright 2023, Hensoldt Cyber
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "OS_Error.h"
#include "OS_Types.h"
#include "OS_Dataport.h"
#include "lib_debug/Debug.h"

#include <autoconf.h>
#include <camkes.h>
#include <stdio.h>
#include <virtqueue.h>
#include <camkes/virtqueue.h>
#include <utils/util.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "network/OS_NetworkTypes.h"
#include "network/OS_NetworkStackTypes.h"


typedef struct
{
    void*  buf;
    size_t len;
} buffer_t;

#define NULL_BUFFER (buffer_t) { .buf = NULL, .len = 0 }


typedef struct
{
    bool init_ok;
    bool driver_init;
    virtqueue_device_t recv_virtqueue;
    virtqueue_driver_t send_virtqueue;
    OS_Dataport_t nic_port_to;
    OS_Dataport_t nic_port_from;
    OS_SharedBuffer_t nw_buffer_to;
    OS_SharedBuffer_t nw_buffer_from;
} ctx_t;

ctx_t the_ctx =
{
    .nic_port_from = OS_DATAPORT_ASSIGN(nic_from_port),
    .nic_port_to = OS_DATAPORT_ASSIGN(nic_to_port),
    .driver_init = false,
    .init_ok = false,
};


static inline buffer_t get_sub_buffer(buffer_t* buffer, size_t offset)
{
    if (offset > buffer->len)
    {
        return NULL_BUFFER;
    }

    return (buffer_t)
    {
        .buf = (void*)((uintptr_t)buffer->buf + offset),
        .len = buffer->len - offset,
    };
}

static inline buffer_t get_sub_buffer_with_min_len(buffer_t* buffer,
                                                   size_t offset,
                                                   size_t min_len)
{
    buffer_t sub_buffer = get_sub_buffer(buffer, offset);
    assert(sub_buffer.buf || (0 == sub_buffer.len));
    return (sub_buffer.len < min_len) ? NULL_BUFFER : sub_buffer;
}

// This function is useful for debugging purposes
static inline void print_packet(buffer_t* packet, char const* info_str)
{
    printf("Packet Contents for %s:\n", info_str);
    for (int i = 0; i < packet->len; i++)
    {
        if (i % 16 == 0)
        {
            printf("%s    0x%03x: ", (i > 0) ? "\n" : "", i);
        }
        printf("%s%02x ",
               (i % 4 == 0) ? " " : "",
               ((uint8_t const*)packet->buf)[i]);
    }
    printf("\n");
    if (packet->len < sizeof(struct ethhdr))
    {
        printf("    invalid ethernet packet with length %zu", packet->len);
        return;
    }
    struct ethhdr const* eth_req = packet->buf;
    printf("    Ethernet Header - src: ");
    for (int i = 0; i < sizeof(eth_req->h_source); i++)
    {
        printf("%s%02x", (i > 0) ? ":" : "", eth_req->h_source[i]);
    }
    printf(" | dst: ");
    for (int i = 0; i < sizeof(eth_req->h_source); i++)
    {
        printf("%s%02x", (i > 0) ? ":" : "", eth_req->h_dest[i]);
    }
    uint16_t protocol = ntohs(eth_req->h_proto);
    printf(" | protocol: 0x%x\n", protocol);

    switch (protocol)
    {
    case ETH_P_ARP:
    {
        printf("    no decoder available, ARP paylaod starts at offset 0x%zx\n",
               sizeof(struct ethhdr));
        return;
    }
    case ETH_P_IPV6:
    {
        printf("    no decoder available, IPv6 paylaod starts at offset 0x%zx\n",
               sizeof(struct ethhdr));
        return;
    }
    case ETH_P_IP:
        break;
    default:
        printf("    no decoder available, paylaod starts at offset 0x%zx\n",
               sizeof(struct ethhdr));
        return;
    }

    buffer_t ip_packet = get_sub_buffer_with_min_len(packet,
                                                     sizeof(struct ethhdr),
                                                     sizeof(struct iphdr));
    if (!ip_packet.buf)
    {
        printf("    invalid IP packet");
        return;
    }
    struct iphdr const* ip = ip_packet.buf;
    struct in_addr saddr = {ip->saddr};
    struct in_addr daddr = {ip->daddr};
    printf("    IP Header - Version: IPv%d protocol: %d | src address: %s",
           ip->version, ip->protocol, inet_ntoa(saddr));
    printf(" | dest address: %s\n", inet_ntoa(daddr));
    switch (ip->protocol)
    {
    case IPPROTO_ICMP:
    {
        buffer_t icmp_packet = get_sub_buffer_with_min_len(&ip_packet,
                                                           sizeof(struct iphdr),
                                                           sizeof(struct icmphdr));

        if (!icmp_packet.buf)
        {
            printf("invalid ICMP packet");
            return;
        }
        struct icmphdr const* icmp = icmp_packet.buf;
        printf("    ICMP Header - Type: %d | id: %d | seq: %d\n",
               icmp->type, icmp->un.echo.id, icmp->un.echo.sequence);
        return;
    }
    default:
        // content dumping not supported for IPPROTO_TCP, IPPROTO_UDP ...
        printf("    no content decoder available\n");
        return;
    }
    UNREACHABLE();
}


// Data TRENTOS -> VM
OS_Error_t nic_rpc_tx_data(size_t* pLen)
{
    ctx_t* ctx = &the_ctx;
    virtqueue_driver_t* vq = &(ctx->send_virtqueue);

    if (!ctx->driver_init)
    {
        Debug_LOG_TRACE("Packet dropped");
        //buffer_t buffer = (buffer_t) {.buf = ctx->nw_buffer_from.buffer, .len = *pLen};
        //print_packet(&buffer, "Drop Packet (Filter -> VM)");
        return OS_SUCCESS;
    }

    size_t len = *pLen;
    *pLen = 0;

    if (len > ctx->nw_buffer_from.len)
    {
        Debug_LOG_ERROR("can't send frame, len %zu exceeds max supported length %lu",
                        len, ctx->nw_buffer_from.len);
        return OS_ERROR_GENERIC;
    }

    int err = camkes_virtqueue_driver_scatter_send_buffer(vq,
                                                          ctx->nw_buffer_from.buffer, len);
    if (err)
    {
        Debug_LOG_ERROR("Failed to send data through virtqueue");
        return -1;
    }

    vq->notify();

    *pLen = len;
    return OS_SUCCESS;
}


//Data VM -> TRENTOS
OS_Error_t nic_rpc_rx_data(size_t* pLen, size_t* framesRemaining)
{
    ctx_t* ctx = &the_ctx;
    virtqueue_device_t* vq = &(ctx->recv_virtqueue);


    virtqueue_ring_object_t handle = { 0 };
    if (!virtqueue_get_available_buf(vq, &handle))
    {
        Debug_LOG_TRACE("Client virtqueue dequeue failed");
        *pLen = 0;
        *framesRemaining = 0;
        return OS_SUCCESS;
    }

    OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)
                                        ctx->nw_buffer_to.buffer;

    size_t len = virtqueue_scattered_available_size(vq, &handle);
    if (camkes_virtqueue_device_gather_copy_buffer(vq, &handle, nw_rx->data,
                                                   len) < 0)
    {
        Debug_LOG_ERROR("Dropping Frame: Available size to read size mismatch");
        return OS_ERROR_GENERIC;
    }

    nw_rx->len = len;
    *pLen = len;

    vq->notify();

    //we do not know how many frames are left
    // -> network stack will ask for more until none are available
    *framesRemaining = 1;
    return OS_SUCCESS;
}


OS_Error_t nic_rpc_get_mac_address(void)
{
    ctx_t* ctx = &the_ctx;
    OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)
                                        ctx->nw_buffer_to.buffer;

    static const uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34 };
    Debug_LOG_TRACE("[NIC '%s'] %s()", get_instance_name(), __func__);
    memcpy(nw_rx->data, mac, 6);

    return OS_SUCCESS;
}


static inline void handle_send_callback(ctx_t* ctx)
{
    virtqueue_driver_t* vq = &(ctx->send_virtqueue);

    virtqueue_ring_object_t handle = {0};
    uint32_t wr_len = 0;
    if (!virtqueue_get_used_buf(vq, &handle, &wr_len))
    {
        Debug_LOG_ERROR("Client virtqueue dequeue failed");
        return;
    }

    for (;;)
    {
        void* buf = NULL;
        unsigned int buf_size = 0;
        vq_flags_t flag = 0;

        int err = camkes_virtqueue_driver_gather_buffer(vq, &handle, &buf,
                                                        &buf_size, &flag);
        if (err)
        {
            if (-1 != err)
            {
                Debug_LOG_ERROR("Unexpected failure %d getting driver queue buffer",
                                err);
            }
            break;
        }

        // Clean up and free the buffer we allocated
        camkes_virtqueue_buffer_free(vq, buf);
    }
}


void virtio_event_callback(void)
{
    ctx_t* ctx = &the_ctx;

    Debug_LOG_TRACE("Received Callback");
    if (!ctx->init_ok)
    {
        Debug_LOG_ERROR("Callback disable due to init failure");
        return;
    }

    if (VQ_DEV_POLL(&(ctx->recv_virtqueue)))
    {
        if (!ctx->driver_init)
        {
            ctx->driver_init = true;
        }
        nic_event_hasData_emit();
        Debug_LOG_TRACE("Data received signal emitted");
    }

    if (VQ_DRV_POLL(&(ctx->send_virtqueue)))
    {
        handle_send_callback(ctx);
        Debug_LOG_TRACE("Data send signal emitted");
    }

}


void post_init(void)
{
    ctx_t* ctx = &the_ctx;

    Debug_LOG_INFO("Initializing virtionet nic driver");

    //Initialise recv virtqueue
    int err = camkes_virtqueue_device_init(&(ctx->recv_virtqueue), 0);
    if (err)
    {
        Debug_LOG_ERROR("Unable to initialise recv virtqueue");
        return;
    }

    // Initialise send virtqueue
    err = camkes_virtqueue_driver_init(&(ctx->send_virtqueue), 1);
    if (err)
    {
        Debug_LOG_ERROR("Unable to initialise send virtqueue");
        return;
    }

    //init nw buffers
    ctx->nw_buffer_to.buffer	= OS_Dataport_getBuf(ctx->nic_port_to);
    ctx->nw_buffer_to.len 		= OS_Dataport_getSize(ctx->nic_port_to);

    ctx->nw_buffer_from.buffer 	= OS_Dataport_getBuf(ctx->nic_port_from);
    ctx->nw_buffer_from.len 	= OS_Dataport_getSize(ctx->nic_port_from);

    ctx->init_ok = true;
}