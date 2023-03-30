#pragma once
#include "pcap.h"

// ��·�㣺MAC֡�����ֶ�
#define IPV4     0x0800
#define IPV6     0x86DD
#define ARP      0x0806
#define RARP     0x8035
#define PPP      0x880B
// ����Э�顤����

// IPV4Э�������ֶ�
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
//*************����֡�ڵ����ݽṹ**************
// MAC֡�ײ�
typedef struct mac_header {
    u_char desAddress[6];// Ŀ��mac��ַ
    u_char srcAddress[6];// Դmac��ַ
    u_short eth_type;// mac֡����

}mac_header, ethernet_header;

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1; //IP��ַ��1���ֶ�
    u_char byte2; //IP��ַ��2���ֶ�
    u_char byte3; //IP��ַ��3���ֶ�
    u_char byte4; //IP��ַ��4���ֶ�
}ip_address;

// IPv4 �ײ� 
// 4�ֽڵ�IP��ַ�����ӽṹ

//IPͷ�����ܳ���20�ֽ�
typedef struct ip_header
{
#if LITTLE_ENDIAN 
    u_char ihl : 4;    //�ײ�����
    u_char version : 4;//�汾 
#else
    u_char version : 4;//�汾
    u_char ihl : 4;    //�ײ�����
#endif
    u_char tos;		 //��������
    u_short tot_len; //�ܳ���
    u_short id;      //��ʶ��
#if LITTLE_ENDIAN 
    u_short frag_off : 13;//��Ƭƫ��
    u_short flag : 3;     //��־
#else
    u_short flag : 3;     //��־
    u_short frag_off : 13;//��Ƭƫ��
#endif
    u_char ttl;      //����ʱ��
    u_char protocol; //Э��
    u_short chk_sum; //�����
    struct ip_address srcaddr; //ԴIP��ַ
    struct ip_address dstaddr; //Ŀ��IP��ַ
}ip_header;

// IPv6�ײ�
typedef struct iphdr6
{

    u_int   version : 4,			//�汾�������湲ͬ����u_int��32λ
            flowtype : 8,			//������
            flowid : 20;			//����ǩ

    u_short plen;					//��Ч�غɳ���
    u_char nh;						//��һ��ͷ��
    u_char hlim;					//������
    u_short saddr[8];			    //Դ��ַ
    u_short daddr[8];		    	//Ŀ�ĵ�ַ
};

// ARP�ײ�
typedef struct arphdr
{
    u_short ar_hrd;						//Ӳ������
    u_short ar_pro;						//Э������
    u_char ar_hln;						//Ӳ����ַ����
    u_char ar_pln;						//Э���ַ����
    u_short ar_op;						//�����룬1Ϊ���� 2Ϊ�ظ�
    u_char ar_srcmac[6];			//���ͷ�MAC
    u_char ar_srcip[4];				//���ͷ�IP
    u_char ar_destmac[6];			//���շ�MAC
    u_char ar_destip[4];				//���շ�IP
};


// TCP�ײ�

//TCPͷ�����ܳ���20�ֽ�         TCPͷ����TCP���ݰ�����һ�����
typedef struct tcp_header
{
    u_short src_port;   //Դ�˿ں�
    u_short dst_port;   //Ŀ�Ķ˿ں�
    u_int seq_no;       //���к�
    u_int ack_no;       //ȷ�Ϻ�
#if LITTLE_ENDIAN
    u_char reserved_1 : 4; //����6λ�е�4λ�ײ�����
    u_char offset : 4;     //tcpͷ������
    u_char flag : 6;       //6λ��־
    u_char reserved_2 : 2; //����6λ�е�2λ
#else
    u_char offset : 4;     //tcpͷ������
    u_char reserved_1 : 4; //����6λ�е�4λ�ײ�����
    u_char reserved_2 : 2; //����6λ�е�2λ
    u_char flag : 6;    //6λ��־ 
#endif
    u_short wnd_size;   //16λ���ڴ�С
    u_short chk_sum;    //16λTCP�����
    u_short urgt_p;     //16Ϊ����ָ��
}tcp_header;


// UDP�ײ�
typedef struct udp_header {
    u_short sport;          // Դ�˿�(Source port)
    u_short dport;          // Ŀ�Ķ˿�(Destination port)
    u_short len;            // UDP���ݰ�����(Datagram length)
    u_short crc;            // У���(Checksum)
}udp_header;


//ICMPͷ�����ܳ���4�ֽ�
typedef struct icmp_header
{
    u_char type;	  //����
    u_char code;      //����
    u_short chk_sum;  //16λ�����
}icmp_header;

// �ص�����packet_handler��ȡ���ײ���ʱ������ݰ����ȣ������ݰ���Ϣ
typedef struct packet {
    const struct pcap_pkthdr* header;
    const u_char* pkt_data;
}packet;


typedef struct http_packet
{
    CString request_method;  // ��������ķ�������GET��POST��HEAD��OPTIONS��PUT��DELETE��TARCE
    CString request_uri;     // ���������URI����/sample.jsp
    CString request_Protocol_version;// ���������Э���Э��İ汾,��HTTP/1.1

    CString request_accept;  // ���������Accept���� */*
    CString request_referer; // ���������Referer���� http://www.gucas.ac.cn/gucascn/index.aspx
    CString request_accept_language;  // ��������� Accept-language���� zh-cn
    CString request_accept_encoding;  // ��������� Accept_encoding���� gzip��deflate
    CString request_modified_date;  // ���������If-Modified-Since���� Sun,27 Sep 2009 02:33:14 GMT
    CString request_match;         // ���������If-None-Match���� "011d3dc1a3fcal:319"
    CString request_user_agent;  // ���������User-Agent���� Mozilla/4.0(compatible:MSIE 6.0;Windows NT 5.1;SV1;.NET CLR 1.1.4322;.NEt...
    CString request_host;      // ���������Host���� www.gucas.ac.cn
    CString request_connection;// ���������Connection���� Keep-Alive
    CString request_cookie;    // ���������Cookie���� ASP.NET_SessionId=hw15u245x23tqr45ef4jaiqc

    CString request_entity_boy;// ���������ʵ������
    //===================================================================================
    CString respond_Protocol_version; // ������ӦЭ���Э��İ汾,��HTTP/1.1
    CString respond_status;         // ������Ӧ״̬���룬��200
    CString respond_description;  // ������Ӧ״̬������ı���������OK

    CString respond_content_type; // ������Ӧ���ݵ����ͣ���text/html
    CString respond_charset;      // ������Ӧ�ַ�����UTF-8
    CString respond_content_length; // ������Ӧ���ݵĳ��ȣ���9
    CString respond_connection; // ������Ӧ����״̬����close
    CString respond_Cache_Control; // ������Ӧ����״̬����private
    CString respond_X_Powered_By; // ������Ӧ����״̬����ASP.NET
    CString respond_X_AspNet_Version; // ������Ӧ����״̬����1.1.4322
    CString respond_Set_Cookie; // ������Ӧ����״̬����ASP.NET_SessionId=w0qojdwi0welb4550lafq55;path=/

    CString respond_date;       // ������Ӧ���ڣ���fri,23 Oct 2009 11:15:31 GMT
    CString respond_Etag;       // �������޸ģ���"Ocld8a8cc91:319"
    CString respond_server;     // ������Ӧ������lighttpd

    CString respond_entity_boy; // ������Ӧʵ�����壬��IMOld(8);
}http_packet;




// IGMP�ײ�