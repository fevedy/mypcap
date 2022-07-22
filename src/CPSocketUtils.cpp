#include "CPSocketUtils.h"
#include <resolv.h>

void mSleep(unsigned int  MilliSecond)
{
	struct timeval time;

	time.tv_sec = MilliSecond / 1000;//seconds
	time.tv_usec = MilliSecond * 1000 % 1000000;//microsecond

	select(0, NULL, NULL, NULL, &time);
}

CPSocketUtils::CPSocketUtils()
{

}

CPSocketUtils::~CPSocketUtils()
{

}

int CPSocketUtils::OpenTcpSocket()
{
    int reuse = 1;
    int handle = socket( AF_INET, SOCK_STREAM, 0);
    if( handle < 0)
    {
        printf("socket create failed, errno is %d\n", errno);
        return handle;
    }
    setsockopt( handle, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof( reuse));
    //SetNonBlockSocket( handle);
    return handle;
}

int CPSocketUtils::OpenUdpSocket()
{
	int reuse = 1;
	int handle = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	//SetNonBlockSocket(handle);
	return handle;
}

int CPSocketUtils::OpenRawSocket()
{
	int reuse = 1;
	int handle = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	SetNonBlockSocket(handle);
	return handle;
}
int CPSocketUtils::OpenLinkSocket()
{
	int handle;

	if ((handle = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
	{
		printf("socket call failed");
		return -1;
	}
	SetNonBlockSocket(handle);
	return handle;
}

bool CPSocketUtils::SetNonBlockSocket(int handle)
{
    fcntl( handle, F_SETFL, fcntl( handle, F_GETFL) | O_NONBLOCK);
    return true;
}

bool CPSocketUtils::ListenUdpSocket(int &handle, unsigned short port)
{
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);
	if (::bind(handle, (struct sockaddr *) &server, sizeof(server)) != 0)
	{
		return false;
	}
	return true;
}

bool CPSocketUtils::ListenTcpSocket(int &handle, unsigned short port)
{
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);
	int	opt = 1;
	int	len = sizeof( int );

	if ( setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &opt, len ) < 0 )
	{
		if ( handle )
		{
			close( handle );
			handle 	= -1;
		}
		return false;
	}


	if (::bind(handle, (struct sockaddr *) &server, sizeof(server)) == 0)
	{
		return (listen(handle, 64) == 0);
	}
	return false;
}

void CPSocketUtils::CloseSocket(int &handle)
{
    if(handle > 0)
    {
        close(handle);
        handle = -1;
    }
}

int CPSocketUtils::SetTcpSocketTimeout(int handle, int idle, int interval, int times)
{
	int keepAlive = 1;
	setsockopt(handle, SOL_SOCKET, SO_KEEPALIVE, (void *) &keepAlive, sizeof(keepAlive));
	setsockopt(handle, SOL_TCP, TCP_KEEPIDLE, (void*) &idle, sizeof(idle));
	setsockopt(handle, SOL_TCP, TCP_KEEPINTVL, (void *) &interval, sizeof(interval));
	setsockopt(handle, SOL_TCP, TCP_KEEPCNT, (void *) &times, sizeof(times));
	return true;
}

int CPSocketUtils::SetSocketBuffer(int handle, int rcvbuf, int sndbuf)
{
	setsockopt(handle, SOL_SOCKET, SO_RCVBUF, (void *) &rcvbuf, sizeof(rcvbuf));
	setsockopt(handle, SOL_SOCKET, SO_SNDBUF, (void *) &sndbuf, sizeof(sndbuf));
	return 0;
}

int CPSocketUtils::AcceptTcpSocket(int handle, int timeout)
{
	fd_set rset;
	struct timeval tv;
	FD_ZERO(&rset);
	FD_SET(handle, &rset);
	tv.tv_sec = timeout / 1000000;
	tv.tv_usec = timeout % 1000000;
	int	iresult	= select(handle + 1, &rset, NULL, NULL, &tv);
	if (iresult > 0)
	{
		if (FD_ISSET(handle, &rset))
		{
			struct sockaddr_in client;
			socklen_t length = sizeof(client);
			return accept(handle, (struct sockaddr*) &client, &length);
		}
	}
	else if(iresult == 0)
	{
		return 0;
	}
	return -1;
}

int CPSocketUtils::ConnectTcpSocket(int handle, const char *address, unsigned short port)
{
    int status = 0;
    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(port);
    inet_pton(AF_INET, address, &client.sin_addr);
    status = connect( handle, (struct sockaddr *) &client, sizeof(client)) ;

    if (( errno == EINPROGRESS)|| ( errno == EALREADY) || ( errno == EISCONN) || ( errno == EACCES) || ( status != -1))
    {
        if(( status != -1)|| ( errno == EISCONN) || ( errno == EACCES))
        {
            return 0;
        }
        fd_set rset,wset;
        struct timeval tv;
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_SET(handle, &rset);
        FD_SET(handle, &wset);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        select(handle + 1, &rset, &wset, NULL, &tv);
        if(FD_ISSET(handle,&rset) || FD_ISSET(handle,&wset))
        {
            return 0;
        }
        printf("--status:[%d]-EISCONN:[%d][%d][%d][%d]-errno:[%d]-\n", status, EISCONN, EACCES, EINPROGRESS, EALREADY, errno);
        return 1;
    }

    return -1;
}

int CPSocketUtils::Send(
                        int handle,
                        const char *buf,
                        int len,
                        int flags,
                        int selectSec,
                        int selectUsec)
{
    int sendtotal = -1;
    int sendlen = 0;
    fd_set wset;
    struct timeval tv;
    FD_ZERO(&wset);
    FD_SET(handle, &wset);
    tv.tv_sec = selectSec;
    tv.tv_usec = selectUsec % 1000000;
    int result = select( handle + 1, NULL, &wset, NULL, &tv);
    if ( result > 0)
    {
        if ( FD_ISSET( handle, &wset))
        {
            sendtotal = 0;
            while( sendtotal < len)
            {
                sendlen = send( handle, ( buf + sendtotal), ( len - sendtotal) , flags);
                if(sendlen <= 0)
                {
                    perror("-----[send]----:");
                    return -1;
                }
                sendtotal +=  sendlen;
            }
        }
    }
    else if( result == 0)
    {
        printf("-------select time out---------\n");
        perror("-----[select]----:");
    }
    else
    {
        printf("-------select---------\n");
        perror("-----[select]----:");
    }

    return sendtotal;
}

int CPSocketUtils::Recv( int handle, char *buf, int len, int flags)
{
    int recv_total = 0;
    int recvlen = 0;
    int explen = len;
    while ( true)
    {
        recvlen = recv( handle, (char *)&buf[ recv_total], ( explen - recv_total), flags);
        if ( recvlen > 0)
        {
            recv_total += recvlen;
            if (recv_total >= explen)
            {
                break;
            }
        }
        else if (-1 == recvlen)
        {
            if (( 0 == errno) || ( EAGAIN == errno) || ( EINTR == errno) || ( EWOULDBLOCK == errno))
            {
                mSleep(20);
                continue;
            }
            else
            {
                perror("-----recv----:");
                printf("recv return SOCKET_ERROR(-1), recv errno is [%d] - %s\n", errno, strerror(errno));
                return -1;
            }

        }
        else
        {
            perror("-----recv----:");
            printf("recv return %d, recv errno is [%d] - %s\n", recvlen, errno, strerror(errno));
            return 0;
        }
    }
    return recv_total;
}


int CPSocketUtils::Recv(
                            int handle,
                            char *buf,
                            int len,
                            int flags,
                            const int selectSec,
                            const int selectUsec)
{
	fd_set rset;
	struct timeval tv;
	FD_ZERO(&rset);
	FD_SET(handle, &rset);
	tv.tv_sec = selectSec / 1000000;
	tv.tv_usec = selectUsec % 1000000;

	int		result	= select(handle + 1, &rset, NULL, NULL, &tv);

	int		recvlen	= 0;
	if(result > 0)
	{
		if(FD_ISSET(handle,&rset))
		{
			
			int explen = len;
			int recvcnt = 4;
			int recv_total = 0;
			while (recvcnt--)
			{
				recvlen	=  recv(handle, (char *)&buf[recv_total], (explen - recv_total), flags);
				if (recvlen > 0)
				{
					recv_total += recvlen;
					if (recv_total >= explen)    break;
				}
				else if (-1 == recvlen)
				{
					if ((0 == errno) || (errno == EAGAIN) || (EINTR == errno) || (EWOULDBLOCK == errno))
					{
						mSleep(10);
						continue;
					}
					else
					{
						perror("-----recv----:");
						printf("recv return SOCKET_ERROR(-1), recv errno is [%d] - %s\n", errno, strerror(errno));
						return -1;
					}
				
				}
				else
				{
					perror("-----recv----:");
					printf("recv return %d, recv errno is [%d] - %s\n", recvlen, errno, strerror(errno));
					return -1;
				}
			}
			return 	recv_total;		
		}
		else
		{
			printf("----isset select----------\n");
			perror("-----[isset select]----:");
			return -2;
		}
	}
	else if(result == 0)
	{
		return 0;
	}
	else
	{
		printf("----select----------\n");
		perror("-----[select]----:");
	}

	return -1;
}

void CPSocketUtils::ParseAddress(std::string &value, std::string &address, unsigned short &port)
{
	size_t pos = 0;
	if ((pos = value.find(":")) != value.npos)
	{
		address = value.substr(0, pos);
		port = atoi(value.substr(pos + 1).c_str());
	}
	else
	{
		address = "127.0.0.1";
		port = 54321;
	}
}


int	CPSocketUtils::SetSockLingerAttr(
									int handle,
									const int lingerOnOff,
									const  int lingerSec)
{
	if(handle > 0)
	{
		struct linger lingerSet;

		memset( &lingerSet, 0x0, sizeof( linger ) );
		lingerSet.l_onoff = lingerOnOff;
		lingerSet.l_linger = lingerSec;

		int	setRet = setsockopt( handle, SOL_SOCKET, SO_LINGER, ( char* )&lingerSet, sizeof( linger ) );
		return setRet;
	}
	return -1;
}


int	CPSocketUtils::SetSockSendTimeOut(
								int handle,
								const int timeoSec,
								const int timeoUsec )
{
	if(handle > 0)
	{
		struct timeval	sendTimeo;

		memset( &sendTimeo, 0x0, sizeof( timeval ) );
		sendTimeo.tv_sec = timeoSec;
		sendTimeo.tv_usec = timeoUsec;

		int	setRet = setsockopt( handle, SOL_SOCKET, SO_SNDTIMEO, ( char* )&sendTimeo, sizeof( timeval ) );

		return setRet;
	}
	return -1;

}

int	CPSocketUtils::SetSockRecvTimeOut(
								int handle,
								const int timeoSec,
								const int timeoUsec )
{
	if(handle > 0)
	{
		struct timeval	recvTimeo;

		memset( &recvTimeo, 0x0, sizeof( timeval ) );
		recvTimeo.tv_sec = timeoSec;
		recvTimeo.tv_usec = timeoUsec;

		int	setRet = setsockopt( handle, SOL_SOCKET, SO_RCVTIMEO, ( char* )&recvTimeo, sizeof( timeval ) );
		return setRet;
	}
	return -1;

}

int	CPSocketUtils::SetSockNoDelay(int sockFd )
{
	if (sockFd <= 0 )
	{
		return	( -1 );
	}

	int	tcpNoDelay = 1;

	int setRet = setsockopt( sockFd, IPPROTO_TCP, TCP_NODELAY, (const char*)&tcpNoDelay, sizeof( tcpNoDelay ) );

	return	( setRet );
}

char *CPSocketUtils::GetIpbySocket(const int handle)
{
	struct sockaddr_in clientaddr = {0};
	socklen_t		size;
	size								= sizeof(sockaddr_in);
	char	*peerip					= NULL;
	getpeername(handle,(sockaddr*)&clientaddr,&size);
	peerip								= inet_ntoa(clientaddr.sin_addr);

	return peerip;
}

int CPSocketUtils::GetDesAddrbySocket(const int handle,struct sockaddr_in *desaddr)
{
	socklen_t		size;
	size								= sizeof(sockaddr_in);
	getpeername(handle,(sockaddr*)desaddr,&size);
	return 0;
}

int CPSocketUtils::GetIpFromDomain( const char *pszDomain, char *pszIp, char pszIpLen)
{
    if (pszDomain == NULL || pszIp== NULL || strlen( pszDomain) == 0)
    {
        printf("GetIpFromDomain param error\n");
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *res, *cur;
    struct sockaddr_in *addr;
    int ret;
    int find = 0;
    char ipbuf[16]={ 0};

   
    memset( &hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_INET; /* Allow IPv4 */
    hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
    hints.ai_protocol = 0; /* Any protocol */
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo( pszDomain, NULL, &hints, &res);
    if ( ret != 0)
    {
        printf("getaddrinfo failed, code %d,msg:%s\n", ret,gai_strerror(ret));
        strcpy( pszIp, pszDomain);
        return -1;
    }
    
    for ( cur = res; cur != NULL; cur = cur->ai_next)
    {
        addr = (struct sockaddr_in *)cur->ai_addr;
        strncpy( pszIp, inet_ntop( AF_INET, &addr->sin_addr, ipbuf, 16), 16);
        find = 1;
    }
    
    if ( find == 0)
    {
        strcpy( pszIp, pszDomain);
    }
    
    if( res != NULL)
    {
        freeaddrinfo( res);
        res = NULL;
    }
    
    return 0;
}


