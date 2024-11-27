// helpers.h

#ifndef HELPERS_H
#define HELPERS_H

// Define types of client requests
#define TCP_SEND 1
#define TCP_RECV 2
#define TCP_RESP 3
#define TCP_HTTP 4
#define TCP_HTTPS 5
#define UDP_SEND 6
#define UDP_RECV 7
#define UDP_RESP 8
#define UDP_HTTP 9

enum Protocol
{
    TCP,
    UDP,
    QUIC
};

#ifdef _WIN32 // Windows-specific headers

    #define DECLSPEC_NORETURN __declspec(noreturn)
    // #define socklen_t int // For length parameter in getsockopt, recvfrom, etc.
    #define close closesocket
    #define SOCKET_ERROR -1
    #define INVALID_SOCKET -1
    #define WSAEWOULDBLOCK EWOULDBLOCK

    // Ensure correct definitions for Windows versions
    #define _WIN32_WINNT 0x0600 // Windows Vista or later
    // #define WIN32_LEAN_AND_MEAN

    #include <stddef.h>

    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>  // For additional socket functions (e.g., inet_pton, inet_ntop)
    #pragma comment(lib, "Ws2_32.lib") // Link to Winsock library

    #include <stdio.h>
    #include <stdlib.h>
    #include <time.h>
    #include <math.h>  // Ensure math functions like fabs are supported
    #include <ctype.h>


    // Define usleep for Windows (Sleep takes milliseconds, but usleep expects microseconds)
    #define usleep(x) Sleep((x) / 1000)

    // Define ssize_t for Windows
    typedef int ssize_t; 

    #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
    #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
    #endif

    const char* inet_ntop(int af, const void* src, char* dst, int cnt);

#else // Linux-specific headers
    #define _DEFAULT_SOURCE

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <ctype.h>
    #include <getopt.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <sys/time.h>
    #include <errno.h>
    #include <math.h>  // For functions like fabs
    #include <signal.h>
    #include <thread>
    #include <atomic>
    #include <string>
    #include <openssl/bio.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/x509v3.h>
    #include <iostream>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif



#pragma pack(push, 1)
typedef struct client_config 
{
    /* Filled by Client */
    struct sockaddr client_addr; // Client address information (for mode: UDP_SEND), may filled by server if early binding 
    int pktsize;                 // Packet size in bytes
    int pktrate;                 // Transmission rate in Bps
    int pktnum;                  // Number of packets to be sent or received
    int mode;                    // TCP_SEND, TCP_RECV, TCP_RESP, TCP_HTTP, TCP_HTTPs, UDP_SEND, UDP_RECV, UDP_RESP, UDP_HTTP
    bool persist;
} client_config;

typedef struct server_config 
{
    /* Filled by Server */
    struct sockaddr server_addr;   // Server address information (for mode: UDP_RECV)
    int sbufsize;                  // Socket send buffer size at the server side
    int rbufsize;                  // Socket receive buffer size at the server side
    int control_socketfd;          // Control socket for receving requests from clients
    int tcp_connect_socketfd;      // Channel socket (for TCP send/recv)
    int udp_recv_socketfd;         // UDP socked used by start_UltraNetProbe_http_udp_server to receive udp http request
    int poolsize;                  // thread pool size (default 8 threads) 
    char *tcpcca = nullptr;        // TCP congestion control module (applied to all TCP socket created by the server)
    std::string request;           // Store HTTP/HTTPS request message
    SSL_CTX* ssl_ctx;              // SSL context
    std::atomic<int> *tcp_clients;  // # of active tcp connection
    std::atomic<int> *udp_clients;  // # of active udp connection
} server_config;

// Fill by both client and server to exchange config data
// Used by request handler thread to handle the client requests
typedef struct global_config 
{
    client_config client_conf;
    server_config server_conf;
} global_config;

char *my_strdup(const char *str);
struct in_addr resolve_ipv4_address(const char *host);
void capitalize_string(char *str);
int create_socket(int domain, int type, int protocol);
int bind_socket(int socketfd, int port, char *lhost);
int send_data_udp(int socketfd, const char *buf, int buf_len, int flags, struct addrinfo *addr_info);
int send_data_tcp(int socketfd, const char *buf, int buf_len, int flags);
void verify_server_address(struct sockaddr *socket_addr);
void print_socket_info(int socket_fd);
int set_tcp_congestion_control(int socket_fd, const char *tcpcca);
int set_socket_buffer_sizes(int socketfd, int rbufsize, int sbufsize);
int parse_url(const char *url, char **hostname, char **port, char **path);
void clean_up(int socketfd, struct addrinfo *addr_info, char *buf);
void perform_dummy_tcp_connect(const char* host, unsigned short port);
void perform_dummy_udp_sendto(const char* host, unsigned short port);

#endif // HELPERS_H