
// snifferDlg.h: 头文件
//

#pragma once
#include "MyWinPcap.h"
#include "afxcmn.h"
#include "afxwin.h"
#define M_MESSAGEWINPCAP (WM_USER+1050)// 缓存的消息数量

// CsnifferDlg 对话框
class CsnifferDlg : public CDialogEx
{
// 构造
public:
	CsnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
	// Create thread handle
	HANDLE m_hdlThread; // Initial




public:
	afx_msg void OnCbnSelchangeWindowTileVert();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnTvnSelchangedTree1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMCustomdrawList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnCbnDropdownCombo1();
	CComboBox combox1;
	CListCtrl list1;
	afx_msg void OnBnClickedButton3();
	afx_msg void OnEnChangeEdit9();
	afx_msg void OnBnClickedButton2();
	CEdit edit;

	afx_msg LRESULT OnMessageWinPcap(WPARAM wParam, LPARAM lParam);// 处理消息函数
	afx_msg void OnNMDblclkList1(NMHDR* pNMHDR, LRESULT* pResult);
	// 实例化自定义类MyWinPcap的对象
	MyWinPcap tmpMyWinPcap;
	CTreeCtrl m_treeDetailInfo;
	// 写于数量
	u_int all_ptk_count;
	u_int all_ptk_ip;
	u_int all_ptk_arp;
	u_int all_ptk_tcp;
	u_int all_ptk_udp;
	u_int all_ptk_icmp;
	u_int all_ptk_rarp;
	u_int all_ptk_igmp;

	// 获取正确的Mac地址
	void GetMacAddress(TCHAR* eth_dMac, u_char* eth_sMac);
	// 获取正确的Ethernet Type类型
	void GetMacType(CString& eth_strType, u_short eth_Type, bool isFirst);
	// 获取正确的IP Type类型
	void GetIPType(CString& ip_strIP, u_short ip_Type, bool isFirst);
	// 获取IP地址
	void GetIPAddress(TCHAR* ip_Address, ip_address* ip_addr);
	// 显示Mac（Ethernet）协议的详细信息
	void ShowMacDetail(HTREEITEM & tmphItem, const u_char * pkt_data);
	// 显示IP协议的详细信息
	void ShowIPDetail(HTREEITEM &hItem,const u_char *pkt_data);
	// 显示TCP协议的详细信息
	void ShowTCPDetail(HTREEITEM & hItem, const u_char * pkt_data);
	// 显示UDP协议的详细信息
	void GetUDPDetail(HTREEITEM & hItem, const u_char * pkt_data);
	// 显示ICMP协议的详细信息
	void GetICMPDetail(HTREEITEM & hItem, const u_char * pkt_data);
	// 显示Packet Data数据信息
	void GetDataInfo(CEdit & eText, packet *pkt);
	// 显示HTTP协议的详细信息
	void GetHTTPDetail(HTREEITEM & hItem, const u_char *pkt_data);
	// 判断该协议是否为HTTP协议
	bool IsHTTP(const u_char* pkt_data);

	// 在“数据统计”组中，显示接收到的各种协议数据包统计信息
	void ShowStatisticInfo(void);
	afx_msg void OnEnChangeEdit7();
	afx_msg void OnEnChangeEdit1();



	void  analysisData(const struct pcap_pkthdr* header, const u_char* pkt_data);
};
