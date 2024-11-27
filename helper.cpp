#include "helper.hpp"

char *my_strdup(const char *str) {
    size_t len = strlen(str) + 1;
    char *copy = (char *)malloc(len);
    if (copy) {
        memcpy(copy, str, len);
    }
    return copy;
}

// // Resolve in_addr structure given the domain name or ip address in char*
// struct in_addr get_in_addr(const char *host, int ai_family, int ai_socktype) {
//     struct addrinfo hints, *result, *rp;
//     struct in_addr addr;

//     // Clear the hints structure and set up for TCP/IPv4
//     memset(&hints, 0, sizeof(struct addrinfo));
//     hints.ai_family = ai_family;
//     hints.ai_socktype = ai_socktype;

//     getaddrinfo(host, NULL, &hints, &result);
    
//     // Find the first valid result
//     for (rp = result; rp != NULL; rp = rp->ai_next) {
//         if (rp->ai_family == AF_INET) {
//             struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
//             addr = ipv4->sin_addr;
//             freeaddrinfo(result);
//             return addr;
//         }
//     }

//     fprintf(stderr, "No suitable address found for %s\n", host);
//     addr.s_addr = INADDR_NONE;
//     freeaddrinfo(result);
//     return addr;
// }

// Resolves a hostname to an IPv4 address
struct in_addr resolve_ipv4_address(const char *host) {
    struct addrinfo hints, *result, *rp;
    struct in_addr addr;

    // Clear the hints structure and set up for IPv4
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;  // IPv4 addresses

    if (getaddrinfo(host, NULL, &hints, &result) != 0) {
        fprintf(stderr, "Error resolving host %s\n", host);
        addr.s_addr = INADDR_NONE;
        return addr;
    }

    // Find the first valid result
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
            addr = ipv4->sin_addr;
            freeaddrinfo(result);
            return addr;
        }
    }

    fprintf(stderr, "No suitable address found for %s\n", host);
    addr.s_addr = INADDR_NONE;
    freeaddrinfo(result);
    return addr;
}

void capitalize_string(char *str)
{
    if (str == NULL) return;

    for (char *p = str; *p; ++p)
    {
        *p = toupper(*p);
    }
}

int create_socket(int domain, int type, int protocol)
{
    int socketfd = socket(domain, type, protocol);
    if (socketfd == -1)
    {
        perror("Error: create_socket() fails! \n");
        return -1;
    }
    return socketfd;
}

int bind_socket(int socketfd, int port, char *lhost)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = (lhost == NULL) ? INADDR_ANY : resolve_ipv4_address(lhost).s_addr;

    if (bind(socketfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("Bind failed\n");
        close(socketfd);
        return -1;
    }

    return socketfd;
}

int send_data_udp(int socketfd, const char *buf, int buf_len, int flags, struct addrinfo *addr_info)
{
    int r = sendto(socketfd, buf, buf_len, flags, addr_info->ai_addr, addr_info->ai_addrlen);
    if (r == -1)
    {
        perror("Error: send_data_udp() fails! \n");

        #ifdef _WIN32 // Windows
            int error_code = WSAGetLastError();
            printf("sendto failed with error code: %d\n", error_code);
        #else
            printf("sendto failed with error code: %d\n", errno);
        #endif

        return -1;

    }

    // printf("Sent %d number of bytes at send_data_udp(). \n", r);
    return r;
}

int send_data_tcp(int socketfd, const char *buf, int buf_len, int flags)
{
    int bytes_sent = 0;
    int r;

    while (bytes_sent < buf_len)
    {
        r = send(socketfd, buf + bytes_sent, buf_len - bytes_sent, flags);

        if (r > 0)
        {
            bytes_sent += r;
        } 
        else if (r == 0)
        {
            printf("Connection closed by peer.\n");
            break;
        } 
        else
        {
            // An error occurred, print error message and exit loop
            // perror("Error in send_data_tcp, sleep for 1 second.");
            // usleep(1000000);
        }
    }

    // printf("Sent %d number of bytes at send_data_tcp(). \n", bytes_sent);
    return bytes_sent;
}

void clean_up(int socketfd, struct addrinfo *addr_info, char *buf)
{
    // Free the addrinfo structure if it's not NULL
    if (addr_info != NULL)
    {
        freeaddrinfo(addr_info);
    }
    
    // Free the buffer if it's not NULL
    if (buf != NULL)
    {
        free(buf);
    }

#ifdef _WIN32 // Windows
    closesocket(socketfd);
    WSACleanup();
#else  // Linux
    close(socketfd);       
#endif
}

void verify_server_address(struct sockaddr *socket_addr)
{
    if (socket_addr->sa_family != AF_INET) {
        printf("Error: Invalid address family. Expecting IPv4.\n");
        return;
    }

    struct sockaddr_in *addr_in = (struct sockaddr_in *)socket_addr;
    char server_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr_in->sin_addr), server_ip, INET_ADDRSTRLEN);
    int server_port = ntohs(addr_in->sin_port);

    printf("Server address: %s\n", server_ip);
    printf("Server port: %d\n", server_port);
}

void print_socket_info(int socket_fd)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if (getsockname(socket_fd, (struct sockaddr *)&addr, &addr_len) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
    int port = ntohs(addr.sin_port);

    printf("socket infor: IP address: %s, Port: %d\n", ip_str, port);
}

#ifdef __linux__
int set_tcp_congestion_control(int socket_fd, const char *tcpcca) {
    if (tcpcca != NULL) {
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_CONGESTION, tcpcca, strlen(tcpcca)) < 0) {
            perror("Error: Unsupported or invalid TCP congestion control algorithm");
            close(socket_fd);
            return -1;
        } else {
            // printf("TCP congestion control algorithm set to: %s for %s\n", tcpcca, context ? context : "socket");
        }
    }
    return 0;  // Success
}
#endif

int set_socket_buffer_sizes(int socketfd, int rbufsize, int sbufsize) {
    // Set the receive buffer size if specified
    if (rbufsize > 0) {
        #ifdef _WIN32
            if (setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, (const char *)&rbufsize, sizeof(rbufsize)) == -1) {
        #else
            if (setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, &rbufsize, sizeof(rbufsize)) == -1) {
        #endif
            perror("Error: setsockopt() failed to set receive buffer size");
            return -1;  // Return error code to indicate failure
        }
    }

    // Set the send buffer size if specified
    if (sbufsize > 0) {
        #ifdef _WIN32
            if (setsockopt(socketfd, SOL_SOCKET, SO_SNDBUF, (const char *)&sbufsize, sizeof(sbufsize)) == -1) {
        #else
            if (setsockopt(socketfd, SOL_SOCKET, SO_SNDBUF, &sbufsize, sizeof(sbufsize)) == -1) {
        #endif
            perror("Error: setsockopt() failed to set send buffer size");
            return -1;  // Return error code to indicate failure
        }
    }

    return 0;  // Success
}

#include <string.h>
#include <stdlib.h>

int parse_url(const char *url, char **hostname, char **port, char **path) {
    const char *url_ptr = url;

    // Skip the protocol if present
    if (strncmp(url_ptr, "http://", 7) == 0) {
        url_ptr += 7;
    } else if (strncmp(url_ptr, "https://", 8) == 0) {
        url_ptr += 8;
    }

    // Extract the hostname
    const char *host_start = url_ptr;
    const char *host_end = strpbrk(url_ptr, ":/");

    if (host_end == NULL) {
        // URL ends after hostname
        *hostname = strdup(host_start);
        *port = NULL;  // Default port
        *path = strdup("/");
        return 0;
    }

    *hostname = strndup(host_start, host_end - host_start);

    // Check if port is specified
    if (*host_end == ':') {
        // Port is specified
        const char *port_start = host_end + 1;
        const char *port_end = strpbrk(port_start, "/");
        if (port_end == NULL) {
            // URL ends after port
            *port = strdup(port_start);
            *path = strdup("/");
            return 0;
        } else {
            *port = strndup(port_start, port_end - port_start);
            *path = strdup(port_end);
            return 0;
        }
    } else if (*host_end == '/') {
        // No port specified
        *port = NULL;  // Default port
        *path = strdup(host_end);
        return 0;
    }

    return -1;  // Should not reach here
}

// Function to perform a dummy TCP connect to a given host and port
void perform_dummy_tcp_connect(const char* host, unsigned short port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Dummy TCP connect: socket creation failed");
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert host to binary form
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("Dummy TCP connect: invalid address");
        close(sockfd);
        return;
    }

    // Attempt to connect (this will unblock accept())
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        // It's possible that the accept is already unblocked by the shutdown listener closing the socket
        // or the socket was already closed. This is normal during shutdown.
        // perror("Dummy TCP connect: connect failed");
    }

    // Immediately close the socket as it's only meant to unblock accept()
    close(sockfd);
}

// Function to perform a dummy UDP sendto to a given host and port
void perform_dummy_udp_sendto(const char* host, unsigned short port) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Dummy UDP sendto: socket creation failed");
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert host to binary form
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("Dummy UDP sendto: invalid address");
        close(sockfd);
        return;
    }

    // Dummy message
    const char* dummy_msg = "shutdown";

    // Send the dummy message
    if (sendto(sockfd, dummy_msg, strlen(dummy_msg), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Dummy UDP sendto: sendto failed");
    }

    // Close the socket
    close(sockfd);
}



#ifdef _WIN32 // Windows
const char* inet_ntop(int af, const void* src, char* dst, int cnt)
{
    struct sockaddr_in srcaddr;
    wchar_t wdst[INET6_ADDRSTRLEN];
    DWORD dstlen = INET6_ADDRSTRLEN;

    memset(&srcaddr, 0, sizeof(struct sockaddr_in));
    memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));

    srcaddr.sin_family = af;
    if (WSAAddressToStringW((struct sockaddr*)&srcaddr, sizeof(struct sockaddr_in), 0, wdst, &dstlen) != 0) {
        DWORD rv = WSAGetLastError();
        printf("WSAAddressToStringW() : %d\n", rv);
        return NULL;
    }

    // Convert wide-character string to narrow-character string
    wcstombs(dst, wdst, cnt);

    return dst;
}
#endif

