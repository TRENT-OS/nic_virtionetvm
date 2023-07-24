/*
 * Copyright 2023, Hensoldt Cyber
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



//----------------------------------------------------------------------
// Context
//----------------------------------------------------------------------


typedef struct {
    bool init_ok;
    bool driver_init;
    virtqueue_device_t recv_virtqueue;
    virtqueue_driver_t send_virtqueue;
    OS_Dataport_t nic_port_to;
    OS_Dataport_t nic_port_from;
    OS_SharedBuffer_t nw_buffer_to;
    OS_SharedBuffer_t nw_buffer_from;
} ctx_t;

ctx_t the_ctx = {
    .nic_port_from = OS_DATAPORT_ASSIGN(nic_from_port),
    .nic_port_to = OS_DATAPORT_ASSIGN(nic_to_port),
    .driver_init = false,
    .init_ok = false,
};



//----------------------------------------------------------------------
// if_OS_NIC interface functions
//----------------------------------------------------------------------


// Data TRENTOS -> VM
OS_Error_t nic_rpc_tx_data(size_t* pLen) {
    ctx_t* ctx = &the_ctx;
    virtqueue_driver_t* vq = &(ctx->send_virtqueue);

    if (!ctx->driver_init) {
        Debug_LOG_TRACE("Packet dropped, driver not initialized");
        return OS_SUCCESS;
    }

    size_t len = *pLen;
    *pLen = 0;

    if (len > ctx->nw_buffer_from.len) {
        Debug_LOG_ERROR("can't send frame, len %zu exceeds max supported length %lu",
                        len, ctx->nw_buffer_from.len);
        return OS_ERROR_GENERIC;
    }

    int err = camkes_virtqueue_driver_scatter_send_buffer(vq,
                                                          ctx->nw_buffer_from.buffer, len);
    if (err) {
        Debug_LOG_ERROR("Failed to send data through virtqueue");
        return -1;
    }

    vq->notify();

    *pLen = len;
    return OS_SUCCESS;
}


//Data VM -> TRENTOS
OS_Error_t nic_rpc_rx_data(size_t* pLen, size_t* framesRemaining) {
    ctx_t* ctx = &the_ctx;
    virtqueue_device_t* vq = &(ctx->recv_virtqueue);

    virtqueue_ring_object_t handle = { 0 };
    if (!virtqueue_get_available_buf(vq, &handle)) {
        Debug_LOG_TRACE("Client virtqueue dequeue failed");
        *pLen = 0;
        *framesRemaining = 0;
        return OS_SUCCESS;
    }

    OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)
                                        ctx->nw_buffer_to.buffer;

    size_t len = virtqueue_scattered_available_size(vq, &handle);
    if (camkes_virtqueue_device_gather_copy_buffer(vq, &handle, nw_rx->data,
                                                   len) < 0) {
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


OS_Error_t nic_rpc_get_mac_address(void) {
    ctx_t* ctx = &the_ctx;
    OS_NetworkStack_RxBuffer_t* nw_rx = (OS_NetworkStack_RxBuffer_t*)
                                        ctx->nw_buffer_to.buffer;

    static const uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34 };
    Debug_LOG_TRACE("[NIC '%s'] %s()", get_instance_name(), __func__);
    memcpy(nw_rx->data, mac, 6);

    return OS_SUCCESS;
}



//----------------------------------------------------------------------
// Callbacks
//----------------------------------------------------------------------


static inline void handle_send_callback(ctx_t* ctx) {
    virtqueue_driver_t* vq = &(ctx->send_virtqueue);

    virtqueue_ring_object_t handle = {0};
    uint32_t wr_len = 0;

    if (!virtqueue_get_used_buf(vq, &handle, &wr_len)) {
        Debug_LOG_ERROR("Client virtqueue dequeue failed");
        return;
    }

    for (;;) {
        void* buf = NULL;
        unsigned int buf_size = 0;
        vq_flags_t flag = 0;

        int err = camkes_virtqueue_driver_gather_buffer(vq, &handle, &buf,
                                                        &buf_size, &flag);
        if (err) {
            if (-1 != err) {
                Debug_LOG_ERROR("Unexpected failure %d getting driver queue buffer",
                                err);
            }
            break;
        }

        // Clean up and free the buffer we allocated
        camkes_virtqueue_buffer_free(vq, buf);
    }
}


void virtio_event_callback(void) {
    ctx_t* ctx = &the_ctx;

    Debug_LOG_TRACE("Received Callback");
    if (!ctx->init_ok) {
        Debug_LOG_ERROR("Callback disable due to init failure");
        return;
    }

    if (VQ_DEV_POLL(&(ctx->recv_virtqueue))) {
        if (!ctx->driver_init) {
            ctx->driver_init = true;
        }
        nic_event_hasData_emit();
        Debug_LOG_TRACE("Data received signal emitted");
    }

    if (VQ_DRV_POLL(&(ctx->send_virtqueue))) {
        handle_send_callback(ctx);
        Debug_LOG_TRACE("Data send signal emitted");
    }
}



//----------------------------------------------------------------------
// Init
//----------------------------------------------------------------------


void post_init(void) {
    ctx_t* ctx = &the_ctx;
    int err;

    Debug_LOG_INFO("Initializing virtionet nic driver");

    //Initialise recv virtqueue
    if ((err = camkes_virtqueue_device_init(&(ctx->recv_virtqueue), 0))) {
        Debug_LOG_ERROR("Unable to initialise recv virtqueue");
        return;
    }

    // Initialise send virtqueue
    if ((err = camkes_virtqueue_driver_init(&(ctx->send_virtqueue), 1))) {
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