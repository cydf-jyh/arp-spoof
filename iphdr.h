#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t vs_ihl_;
	uint8_t dscp_ecn_;
	uint16_t tot_ln_;
	uint16_t id_;
	uint16_t flag_fo_;
	uint8_t ttl_;
	uint8_t protocol_;
	uint16_t hcs_;
	Ip       sip_;
	Ip       dip_;
    
	uint8_t vs_ihl()  { return vs_ihl_; }
	uint8_t dscp_ecn()  { return dscp_ecn_; }
	uint16_t tot_ln()  { return tot_ln_; }
	uint16_t id()  { return id_; }
	uint16_t flag_fo()  { return flag_fo_; }
	uint8_t ttl()  { return ttl_; }
	uint8_t protocol()  { return protocol_; }
	uint16_t hcs()  { return hcs_; }
	Ip       sip()  { return ntohl(sip_); }
	Ip       dip()  { return ntohl(dip_); }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
