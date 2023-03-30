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
	CFile* m_pfileData;  // �������ݰ����ļ�
	CFile* m_pfileIndex; // ���ݰ������ļ�
	int m_iCurNo;       // ��ǰ���λ��

// ============ self funciton ============
// file
public:
	void AppendPacket(packet* pkt);
	packet* GetPacket(int m_iNo);

	//=======================
	// operation function
public:
	// ���ر������е�����
	pcap_if_t* GetAdapterList(void);



};

#endif
