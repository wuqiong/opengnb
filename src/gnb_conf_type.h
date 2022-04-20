/*
   Copyright (C) gnbdev

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef GNB_CONF_TYPE_H
#define GNB_CONF_TYPE_H

#include <stdint.h>
#include <limits.h>

#ifdef _WIN32

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#endif


#define GNB_PF_TYPE_CRYPTO_NONE    0x0
#define GNB_PF_TYPE_CRYPTO_XOR     0x01
#define GNB_PF_TYPE_CRYPTO_ARC4    0x02
#define GNB_PF_TYPE_CRYPTO_AES     0x03

#define GNB_CRYPTO_KEY_UPDATE_INTERVAL_NONE    0x0
#define GNB_CRYPTO_KEY_UPDATE_INTERVAL_MINUTE  0x1
#define GNB_CRYPTO_KEY_UPDATE_INTERVAL_HOUR    0x2

#define GNB_MULTI_ADDRESS_TYPE_SIMPLE_FAULT_TOLERANT    0x1
#define GNB_MULTI_ADDRESS_TYPE_SIMPLE_LOAD_BALANCE      0x2
#define GNB_MULTI_ADDRESS_TYPE_FULL                     0x3

#define GNB_WORKER_MIN_QUEUE         16
#define GNB_WORKER_MAX_QUEUE         4096

typedef struct _gnb_conf_t {

	char conf_dir[PATH_MAX];

	uint8_t public_index_service;
	uint8_t lite_mode;

	uint32_t local_uuid;

	char binary_dir[PATH_MAX];

	char map_file[PATH_MAX+NAME_MAX];

	char pid_file[PATH_MAX+NAME_MAX];

	char node_cache_file[PATH_MAX+NAME_MAX];

	char log_path[PATH_MAX];

	uint8_t console_log_level;
	uint8_t file_log_level;
	uint8_t udp_log_level;

	uint8_t core_log_level;
	uint8_t pf_log_level;
	uint8_t main_log_level;
	uint8_t node_log_level;
	uint8_t index_log_level;
	uint8_t index_service_log_level;
	uint8_t detect_log_level;

	uint8_t log_udp_type;

	char log_udp_sockaddress4_string[16 + 1 + sizeof("65535") + 1];

	char ifname[256];

	//根据 IFNAMSIZ 定义为16
	char socket_ifname[16];

	int mtu;

	unsigned char crypto_type;
	unsigned char crypto_key_update_interval;
	unsigned char crypto_passcode[4];

	unsigned char multi_index_type;
	unsigned char multi_forward_type;

	unsigned char if_dump;

	unsigned char udp_socket_type;

	uint8_t multi_socket;

	char pf_route[NAME_MAX];

	uint8_t pf_route_mode;

    #define GNB_UNIFIED_FORWARDING_OFF    0
    #define GNB_UNIFIED_FORWARDING_AUTO   1
    #define GNB_UNIFIED_FORWARDING_FORCE  2
    #define GNB_UNIFIED_FORWARDING_FULL   3
	uint8_t unified_forwarding;

	uint8_t direct_forwarding;


    #define GNB_IF_DRV_TYPE_DEFAULT        0x0
    #define GNB_IF_DRV_TYPE_TAP_WINDOWS    0xA
    #define GNB_IF_DRV_TYPE_TAP_WINTUN     0xB
	uint8_t if_drv;

	uint8_t activate_tun;
	uint8_t activate_node_worker;
	uint8_t activate_index_worker;
	uint8_t activate_index_service_worker;
	uint8_t activate_detect_worker;

	uint8_t fwdu0;
	unsigned char ufwd_passcode[4];

	char listen_address6_string[46 + 2 + 1 + sizeof("65535") + 1];
	char listen_address4_string[16 + 1 + sizeof("65535") + 1];

	#define GNB_MAX_UDP6_SOCKET_NUM 4
	#define GNB_MAX_UDP4_SOCKET_NUM 16

	//host 格式存放
	uint16_t udp6_ports[GNB_MAX_UDP6_SOCKET_NUM];
	uint16_t udp4_ports[GNB_MAX_UDP4_SOCKET_NUM];

	//upnp 映射的端口，可由 upnp client 写入
	uint16_t udp4_ext_ports[GNB_MAX_UDP4_SOCKET_NUM];

	uint8_t udp6_socket_num;
	uint8_t udp4_socket_num;

	uint16_t node_woker_queue_length;

	uint16_t index_woker_queue_length;
	uint16_t index_service_woker_queue_length;

	uint16_t port_detect_start;
	uint16_t port_detect_end;
	uint16_t port_detect_range;

	uint8_t addr_secure;

	uint8_t daemon;
	uint8_t systemd_daemon;

	uint8_t quiet;

}gnb_conf_t;


typedef struct _gnb_conf_ext_lite_t {

	char *index_address_string;
	char *node_address_string;
	char *node_route_string;

}gnb_conf_ext_lite_t;


#define GNB_CONF_FIELD_SEPARATOR_TYPE_ERROR   -1
#define GNB_CONF_FIELD_SEPARATOR_TYPE_SLASH    0
#define GNB_CONF_FIELD_SEPARATOR_TYPE_VERTICAL 1


#endif
