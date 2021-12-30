/*
 * CSocketUtils.h
 *
 *  Created on: 2011-9-7
 *      Author: stargui
 */

#ifndef CPSOCKETUTILS_H_
#define CPSOCKETUTILS_H_

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <string>

using namespace std;

class CPSocketUtils
{

public:

	CPSocketUtils();

	virtual ~CPSocketUtils();

public:

	static int OpenUdpSocket();

	static int OpenTcpSocket();

	static int OpenRawSocket();

	static int OpenLinkSocket();
	static bool SetNonBlockSocket(int handle);

	static int SetSocketBuffer(int handle, int rcvbuf, int sndbuf);

	static bool ListenTcpSocket(int &handle, unsigned short port);

	static bool ListenUdpSocket(int &handle, unsigned short port);
	static bool ListenLinkSocket(int &handle, char* szInterface);

	static int SetTcpSocketTimeout(int handle, int idle, int interval, int times);

	static int AcceptTcpSocket(int handle, int timeout);

	static int ConnectTcpSocket(int handle, const char *address, unsigned short port);

	static void CloseSocket(int &handle);

	static int  SetSockLingerAttr(
							int handle,
							const int lingerOnOff,
							const int lingerSec);

	static int	SetSockSendTimeOut(
							int handle,
							const int timeoSec,
							const int timeoUsec );

	static int	SetSockRecvTimeOut(
									int handle,
									const int timeoSec,
									const int timeoUsec );

	static int	BindSocketToDevice(
										int handle,
										const char* pDev);

	static int	SetSockNoDelay(int sockFd );

public:

	static int Send(
					int handle,
					const char *buf,
					int len,
					int flags = 0,
					int selectSec = 1,
					int selectUsec = 0);

    static int Recv( int handle, char *buf, int len, int flags);

	static int Recv(
					int handle,
					char *buf,
					int len,
					int flags,
					const int selectSec,
					const int selectUsec);

public:

	static void ParseAddress(std::string &value, std::string &address, unsigned short &port);

	static int Getifindex(const char *interface, int *ifindex);

	static char* GetIpbySocket(const int handle);

	static int GetDesAddrbySocket(const int handle,struct sockaddr_in *desaddr);

	static int GetSrcAddrbySocket(const int handle,struct sockaddr_in *srcaddr);

	static int DelArpByIp(const char *desip, const char *dev);

	static int SetArpByip(char *ip, char *mac, const char *dev);
    static int GetIpFromDomain( const char *pszDomain, char *pszIp, char pszIpLen);
    
public:

	static int RecvPkg(int socket,struct sockaddr_in* from, char* szbuff,  int length,int timeUsec  = 1000000);

	static int SendPkg(int socket,char *szbuff,int szSendbuflen,struct sockaddr_in* to,int timeUsec = 1000000);
};

#endif /* CPSOCKETUTILS_H_ */

