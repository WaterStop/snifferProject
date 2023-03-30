#pragma once
#include "afxdialogex.h"


// RuleFilter 对话框
extern CString filterName; // 过滤规则的字符串
class RuleFilter : public CDialogEx
{
	DECLARE_DYNAMIC(RuleFilter)

public:
	RuleFilter(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~RuleFilter();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCheck7();
	CButton m_tcp;
	CButton m_udp;
	CButton m_arp;
	CButton m_rarp;
	CButton m_icmp;
	CButton m_igmp;




	afx_msg void OnBnClickedCheck6();
	afx_msg void OnBnClickedCheck3();
	afx_msg void OnEnChangeEdit1();
	CEdit editRule;
	afx_msg void OnEnSetfocusEdit1();
	afx_msg void OnEnKillfocusEdit1();
};
