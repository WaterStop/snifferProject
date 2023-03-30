//#pragma once

#ifndef _MYWINPCAP_H_
#define _MYWINPCAP_H_


#include "protocol.h"

class MyWinPcap
{
public:
	MyWinPcap(void);
	~MyWinPcap(void);



	// =============== self var ===============
		// file
private:
	CFile* m_pfileData;  // 保存数据包的文件
	CFile* m_pfileIndex; // 数据包索引文件
	int m_iCurNo;       // 当前序号位置

// ============ self funciton ============
// file
public:
	void AppendPacket(packet* pkt);
	packet* GetPacket(int m_iNo);

	//=======================
	// operation function
public:
	// 返回本机所有的网卡
	pcap_if_t* GetAdapterList(void);



};

#endif
