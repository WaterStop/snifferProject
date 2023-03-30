#pragma once
#include "pcap.h"

// 链路层：MAC帧类型字段
#define IPV4     0x0800
#define IPV6     0x86DD
#define ARP      0x0806
#define RARP     0x8035
#define PPP      0x880B
// 其他协议···

// IPV4协议类型字段
#define TCP        0x06
#define UDP        0x11
#define ICMP       0x01
#define IGMP       0x02
typedef struct packet_index {
    int no;
    ULONGLONG pos;
    int len;
}packet_index;

// i386 is little_endian.
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN   (1)   //BYTE ORDER
#endif
//*************数据帧内的数据结构**************
// MAC帧首部
typedef struct mac_header {
    u_char desAddress[6];// 目的mac地址
    u_char srcAddress[6];// 源mac地址
    u_short eth_type;// mac帧类型

}mac_header, ethernet_header;

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1; //IP地址第1个字段
    u_char byte2; //IP地址第2个字段
    u_char byte3; //IP地址第3个字段
    u_char byte4; //IP地址第4个字段
}ip_address;

// IPv4 首部 
// 4字节的IP地址数据子结构

//IP头部，总长度20字节
typedef struct ip_header
{
#if LITTLE_ENDIAN 
    u_char ihl : 4;    //首部长度
    u_char version : 4;//版本 
#else
    u_char version : 4;//版本
    u_char ihl : 4;    //首部长度
#endif
    u_char tos;		 //服务类型
    u_short tot_len; //总长度
    u_short id;      //标识号
#if LITTLE_ENDIAN 
    u_short frag_off : 13;//分片偏移
    u_short flag : 3;     //标志
#else
    u_short flag : 3;     //标志
    u_short frag_off : 13;//分片偏移
#endif
    u_char ttl;      //生存时间
    u_char protocol; //协议
    u_short chk_sum; //检验和
    struct ip_address srcaddr; //源IP地址
    struct ip_address dstaddr; //目的IP地址
}ip_header;

// IPv6首部
typedef struct iphdr6
{

    u_int   version : 4,			//版本，与下面共同分享u_int的32位
            flowtype : 8,			//流类型
            flowid : 20;			//流标签

    u_short plen;					//有效载荷长度
    u_char nh;						//下一个头部
    u_char hlim;					//跳限制
    u_short saddr[8];			    //源地址
    u_short daddr[8];		    	//目的地址
};

// ARP首部
typedef struct arphdr
{
    u_short ar_hrd;						//硬件类型
    u_short ar_pro;						//协议类型
    u_char ar_hln;						//硬件地址长度
    u_char ar_pln;						//协议地址长度
    u_short ar_op;						//操作码，1为请求 2为回复
    u_char ar_srcmac[6];			//发送方MAC
    u_char ar_srcip[4];				//发送方IP
    u_char ar_destmac[6];			//接收方MAC
    u_char ar_destip[4];				//接收方IP
};


// TCP首部

//TCP头部，总长度20字节         TCP头部与TCP数据包不是一个概念；
typedef struct tcp_header
{
    u_short src_port;   //源端口号
    u_short dst_port;   //目的端口号
    u_int seq_no;       //序列号
    u_int ack_no;       //确认号
#if LITTLE_ENDIAN
    u_char reserved_1 : 4; //保留6位中的4位首部长度
    u_char offset : 4;     //tcp头部长度
    u_char flag : 6;       //6位标志
    u_char reserved_2 : 2; //保留6位中的2位
#else
    u_char offset : 4;     //tcp头部长度
    u_char reserved_1 : 4; //保留6位中的4位首部长度
    u_char reserved_2 : 2; //保留6位中的2位
    u_char flag : 6;    //6位标志 
#endif
    u_short wnd_size;   //16位窗口大小
    u_short chk_sum;    //16位TCP检验和
    u_short urgt_p;     //16为紧急指针
}tcp_header;


// UDP首部
typedef struct udp_header {
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;


//ICMP头部，总长度4字节
typedef struct icmp_header
{
    u_char type;	  //类型
    u_char code;      //代码
    u_short chk_sum;  //16位检验和
}icmp_header;

// 回调函数packet_handler获取的首部（时间和数据包长度）和数据包信息
typedef struct packet {
    const struct pcap_pkthdr* header;
    const u_char* pkt_data;
}packet;


typedef struct http_packet
{
    CString request_method;  // 代表请求的方法，如GET、POST、HEAD、OPTIONS、PUT、DELETE和TARCE
    CString request_uri;     // 代表请求的URI，如/sample.jsp
    CString request_Protocol_version;// 代表请求的协议和协议的版本,如HTTP/1.1

    CString request_accept;  // 代表请求的Accept，如 */*
    CString request_referer; // 代表请求的Referer，如 http://www.gucas.ac.cn/gucascn/index.aspx
    CString request_accept_language;  // 代表请求的 Accept-language，如 zh-cn
    CString request_accept_encoding;  // 代表请求的 Accept_encoding，如 gzip、deflate
    CString request_modified_date;  // 代表请求的If-Modified-Since，如 Sun,27 Sep 2009 02:33:14 GMT
    CString request_match;         // 代表请求的If-None-Match，如 "011d3dc1a3fcal:319"
    CString request_user_agent;  // 代表请求的User-Agent，如 Mozilla/4.0(compatible:MSIE 6.0;Windows NT 5.1;SV1;.NET CLR 1.1.4322;.NEt...
    CString request_host;      // 代表请求的Host，如 www.gucas.ac.cn
    CString request_connection;// 代表请求的Connection，如 Keep-Alive
    CString request_cookie;    // 代表请求的Cookie，如 ASP.NET_SessionId=hw15u245x23tqr45ef4jaiqc

    CString request_entity_boy;// 代表请求的实体主体
    //===================================================================================
    CString respond_Protocol_version; // 代表响应协议和协议的版本,如HTTP/1.1
    CString respond_status;         // 代表响应状态代码，如200
    CString respond_description;  // 代表响应状态代码的文本描述，如OK

    CString respond_content_type; // 代表响应内容的类型，如text/html
    CString respond_charset;      // 代表响应字符，如UTF-8
    CString respond_content_length; // 代表响应内容的长度，如9
    CString respond_connection; // 代表响应连接状态，如close
    CString respond_Cache_Control; // 代表响应连接状态，如private
    CString respond_X_Powered_By; // 代表响应连接状态，如ASP.NET
    CString respond_X_AspNet_Version; // 代表响应连接状态，如1.1.4322
    CString respond_Set_Cookie; // 代表响应连接状态，如ASP.NET_SessionId=w0qojdwi0welb4550lafq55;path=/

    CString respond_date;       // 代表响应日期，如fri,23 Oct 2009 11:15:31 GMT
    CString respond_Etag;       // 代表无修改，如"Ocld8a8cc91:319"
    CString respond_server;     // 代表响应服务，如lighttpd

    CString respond_entity_boy; // 代表响应实体主体，如IMOld(8);
}http_packet;




// IGMP首部