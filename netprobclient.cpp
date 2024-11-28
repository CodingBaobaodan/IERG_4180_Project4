#include "helper.hpp"

#ifdef _WIN32
// Implementing gettimeofday for Windows
int gettimeofday(struct timeval* tp, struct timezone* tzp) {
    FILETIME file_time;
    ULARGE_INTEGER ularge;

    GetSystemTimeAsFileTime(&file_time);
    ularge.LowPart = file_time.dwLowDateTime;
    ularge.HighPart = file_time.dwHighDateTime;

    // Convert to microseconds
    ularge.QuadPart /= 10;

    // Convert to seconds and microseconds
    tp->tv_sec = (long)(ularge.QuadPart / 1000000UL);
    tp->tv_usec = (long)(ularge.QuadPart % 1000000UL);

    return 0;
}
#endif

enum Mode
{
    SEND,
    RECV,
    RESPONSE,
    HTTP,
    HTTPS,
    HOST
};


typedef struct input_client_config
{
    int stat;
    char *rhost;
    char *rport;
    char *protocol;
    char *url;
    char *file; // For displaying the received text files
    Mode mode;
    int pktsize;
    int pktrate;
    int pktnum;
    int sbufsize;
    int rbufsize;
    bool persist;
} input_client_config;

typedef struct host_config {
    char *hostname;
} host_config;

// Add platform-specific initialization for Windows
void InitializeSockets() {
#ifdef _WIN32
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2); // Request Winsock version 2.2
    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("Unable to initialize Winsock! Error: %d\n", err);
        exit(-1);
    }
    if (LOBYTE(wsaData.wVersion) < 2) {
        WSACleanup();
        printf("Incorrect Winsock version. Expected 2.2!\n");
        exit(-1);
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif
}

// Cleanup sockets for Windows
void CleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Function to extract port from a URL and determine the protocol (HTTP or HTTPS)
void extract_port_from_url(input_client_config *config) {
    if (config->url == NULL) {
        return;
    }

    char *url_copy = my_strdup(config->url);
    char *protocol_end = strstr(url_copy, "://");
    if (protocol_end != NULL) {
        protocol_end += 3;  // Skip past "://"
        
        // Check if it's https or http
        if (strncmp(url_copy, "https", 5) == 0) {
            if (strchr(protocol_end, ':') == NULL) {
                // HTTPS specified but no port number
                fprintf(stderr, "Error: HTTPS mode requires a port number in the URL.\n");
                exit(1);
            } else {
                // Set mode to HTTPS
                config->mode = HTTPS;
            }
        } else if (strncmp(url_copy, "http", 4) == 0) {
            // If it's HTTP, we just leave it as is, the mode stays HTTP
            config->mode = HTTP;
        }
        
        // Extract the port if present
        char *port_start = strchr(protocol_end, ':');
        if (port_start != NULL) {
            port_start++;  // Skip ':'
            char *port_end = strchr(port_start, '/');
            if (port_end != NULL) {
                *port_end = '\0';  // End of port, replace '/' with '\0'
            }
            // Set rport to the parsed port number
            free(config->rport);
            config->rport = my_strdup(port_start);
        }
    }

    free(url_copy);
}


input_client_config* parse_client_mode(int argc, char *argv[], Mode mode)
{
    input_client_config *config = (input_client_config *)malloc(sizeof(input_client_config));
    if (!config)
    {
        perror("Failed to allocate memory for send_config\n");
        exit(-1);
    }

    // Set default values
    config->stat = 500;
    config->rhost = my_strdup("localhost");
    config->rport = (mode == HTTP) ? NULL : my_strdup("4180");
    config->protocol = my_strdup("UDP");
    config->pktsize = (mode == RESPONSE) ? 10 : 1000; // mode == 3 means response mode
    config->pktrate = 1000;
    config->pktnum = 0;
    config->sbufsize = 0; 
    config->rbufsize = 0; 
    config->persist = false;
    config->url = NULL;
    config->file = NULL;
    config->mode = mode;
    

    #ifdef _WIN32
    // Windows manual argument parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-stat") == 0 && i + 1 < argc) {
            config->stat = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-rhost") == 0 && i + 1 < argc) {
            free(config->rhost);

            // Extract hostname from URL for -rhost
            char *input_host = argv[++i];
            if (strncmp(input_host, "https://", 8) == 0) {
                input_host += 8;
            } else if (strncmp(input_host, "http://", 7) == 0) {
                input_host += 7;
            }

            // Find the end of the hostname
            char *end = strchr(input_host, '/');
            if (end) {
                *end = '\0';  // Terminate the string at '/'
            }

            config->rhost = my_strdup(input_host);
        } else if (strcmp(argv[i], "-rport") == 0 && i + 1 < argc) {
            free(config->rport);
            config->rport = my_strdup(argv[++i]);
        } else if (strcmp(argv[i], "-proto") == 0 && i + 1 < argc) {
            free(config->protocol);
            config->protocol = my_strdup(argv[++i]);
            capitalize_string(config->protocol);
        } else if (strcmp(argv[i], "-pktsize") == 0 && i + 1 < argc) {
            config->pktsize = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-pktrate") == 0 && i + 1 < argc) {
            config->pktrate = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-pktnum") == 0 && i + 1 < argc) {
            config->pktnum = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-sbufsize") == 0 && i + 1 < argc) {
            config->sbufsize = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-rbufsize") == 0 && i + 1 < argc) {
            config->rbufsize = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-persist") == 0 && i + 1 < argc) {
            capitalize_string(argv[++i]);
            if (strcmp(argv[i], "YES") == 0) {
                config->persist = true;
            } else if (strcmp(argv[i], "NO") == 0) {
                config->persist = false;
            } else {
                fprintf(stderr, "Unknown value for -persist: %s\n", argv[i]);
                exit(-1);
            }
        } else {
            fprintf(stderr, "Unknown option or missing value: %s\n", argv[i]);
            exit(-1);
        }
    }
    #else

    int option;
    static struct option long_options[] =
    {
        {"stat", required_argument, 0, 'a'},
        {"rhost", required_argument, 0, 'b'},
        {"rport", required_argument, 0, 'c'},
        {"proto", required_argument, 0, 'd'},
        {"pktsize", required_argument, 0, 'e'},
        {"pktrate", required_argument, 0, 'f'},
        {"pktnum", required_argument, 0, 'g'},
        {"sbufsize", required_argument, 0, 'h'},
        {"rbufsize", required_argument, 0, 'i'},
        {"persist", required_argument, 0, 'j'},
         {"url", required_argument, 0, 'k'}, 
        {"file", required_argument, 0, 'l'},
        {0, 0, 0, 0}
    };

    char *input_host = NULL;
    char *end = NULL;
    while ((option = getopt_long_only(argc, argv, "", long_options, NULL)) != -1)
    {
        switch (option) {
            // -stat
            case 'a':
                config->stat = atoi(optarg);
                break;
            // -rhost
            case 'b':
                free(config->rhost);

                // Extract hostname from URL for -rhost
                input_host = optarg;
                if (strncmp(input_host, "https://", 8) == 0) {
                    input_host += 8;
                } else if (strncmp(input_host, "http://", 7) == 0) {
                    input_host += 7;
                }

                // Find the end of the hostname
                end = strchr(input_host, '/');
                if (end) {
                    *end = '\0';  // Terminate the string at '/'
                }

                config->rhost = my_strdup(input_host);
                break;
            // -rport
            case 'c':
                (mode == HTTP) ? void() : free(config->rport);
                config->rport = my_strdup(optarg);
                break;
            // -proto
            case 'd':
                free(config->protocol);
                config->protocol = my_strdup(optarg);
                capitalize_string(config->protocol);
                break;
            // -pktsize
            case 'e':
                config->pktsize = atoi(optarg);
                break;
            // -pktrate
            case 'f':
                config->pktrate = atoi(optarg);
                break;
            // -pktnum
            case 'g':
                config->pktnum = atoi(optarg);
                break;
            // -sbufsize
            case 'h':
                config->sbufsize = atoi(optarg);  
                break;
            // -rbufsize
            case 'i':
                config->rbufsize = atoi(optarg);  
                break;
            // -persist
            case 'j':
                capitalize_string(optarg);
                if (strcmp(optarg, "YES") == 0)
                {
                    config->persist = true;
                } 
                else if (strcmp(optarg, "NO") == 0)
                {
                    config->persist = false;
                } 
                else
                {
                    fprintf(stderr, "Unknown value for -persist: %s\n", optarg);
                    exit(-1);
                }
                break;
            // -url
            case 'k':
                config->url = my_strdup(optarg);
                break;
            // -file
            case 'l':
                config->file = my_strdup(optarg);
                break;
            default:
                perror("Unknown option for send mode\n");
                exit(-1);
        }
    }
    #endif

    // URL is required for HTTP/HTTPS mode.
    if (mode == HTTP && config->url == NULL) {
        fprintf(stderr, "Error: URL is required for HTTP/HTTPS mode.\n");
        exit(1);
    }

    // Extract port and determine mode (http or https) from URL
    if (config->url != NULL) {
        extract_port_from_url(config);
    }

    // Set Default HTTP port
    if (config->rport == NULL && mode == HTTP) {
        config->rport = my_strdup("80");  
    }


    // Log print
    if (mode == HTTP)
    {
        printf("HTTP Client config: url=%s, rport=%s, protocol=%s, filename=%s \n",
           config->url, config->rport, config->protocol, config->file);
    }
    else if (mode == HTTPS)
    {
        printf("HTTPS Client config: url=%s, rport=%s, protocol=%s, filename=%s \n",
           config->url, config->rport, config->protocol, config->file);
    }
    else
    {
        printf("Client config: stat=%d, rhost=%s, rport=%s, protocol=%s, pktsize=%d, pktrate=%d, pktnum=%d, sbufsize=%d, rbufsize=%d\n",
           config->stat, config->rhost, config->rport, config->protocol, config->pktsize, config->pktrate, config->pktnum, config->sbufsize, config->rbufsize);
    }
    
    
    return config;
}

host_config* parse_host_mode(int argc, char *argv[]) {
    host_config *config = (host_config *)malloc(sizeof(struct host_config));
    if (!config) {
        perror("Failed to allocate memory for host_config\n");
        exit(-1);
    }

    // Set default values
    config->hostname = my_strdup("localhost");

    #ifdef _WIN32
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-host") == 0 && i + 1 < argc) {
            free(config->hostname);

            // Extract hostname from URL
            char *input_host = argv[++i];
            if (strncmp(input_host, "https://", 8) == 0) {
                input_host += 8;  // Skip "https://"
            } else if (strncmp(input_host, "http://", 7) == 0) {
                input_host += 7;  // Skip "http://"
            }

            // Find the end of the hostname (stop at '/' if there's a path)
            char *end = strchr(input_host, '/');
            if (end) {
                *end = '\0';  // Terminate at the end of hostname
            }

            config->hostname = my_strdup(input_host);
        } else {
            fprintf(stderr, "Unknown option or missing value: %s\n", argv[i]);
            exit(-1);
        }
    }
    #else

    int option;
    static struct option long_options[] = {
        {"host", required_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    char *input_host = NULL;
    char *end = NULL;
    while ((option = getopt_long_only(argc, argv, "", long_options, NULL)) != -1) {
        switch (option) {
            // -host
            case 'a': 
                free(config->hostname);

                // Extract hostname from URL
                input_host = optarg;
                if (strncmp(input_host, "https://", 8) == 0) {
                    input_host += 8;
                } else if (strncmp(input_host, "http://", 7) == 0) {
                    input_host += 7;
                }

                // Find the end of the hostname
                end = strchr(input_host, '/');
                if (end) {
                    *end = '\0'; // mark the end of the string
                }

                config->hostname = my_strdup(input_host);
                break;
                
            default:
                perror("Unknown option for host mode\n");
                exit(-1);
        }
    }
    #endif

    // Log print
    printf("Host mode: hostname=%s\n", config->hostname);
    
    return config;
}

struct addrinfo* get_address(const char *host, const char *port, const char *protocol)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    // The ai_addrlen, ai_canonname, ai_addr, and ai_next members of the 
    // addrinfo structure pointed to by the pHints parameter must be zero or NULL
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = (strcmp("UDP", protocol) == 0) ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = (strcmp("UDP", protocol) == 0) ? IPPROTO_UDP : IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &results) != 0)
    {
        perror("Error: get_address() fails! \n");
        return NULL;
    }
    return results;
}

int create_connection(int socketfd, struct addrinfo *addr_info)
{
    if (connect(socketfd, addr_info->ai_addr, (int)addr_info->ai_addrlen) == -1)
    {
        perror("Error: create_connection() fails! \n");
        close(socketfd);
        return -1;
    }

    return 0;
}

// This function create the TCP socket and send client_config to the server.
// This function will set up the socketfd and addr_info for TCP connection
int send_client_config(int mode, input_client_config *config, int *socketfd, struct addrinfo **addr_info, struct sockaddr *local_sockaddr)
{
    client_config client_conf;
    client_conf.pktsize = config->pktsize;
    client_conf.pktrate = config->pktrate;
    client_conf.pktnum = config->pktnum;
    client_conf.client_addr = *local_sockaddr;
    client_conf.mode = mode;
    client_conf.persist = config->persist;

    *addr_info = get_address(config->rhost, config->rport, "TCP");
    if (*addr_info == NULL)
    {
        return -1;
    }

    // socketfd will be set to -1 if it is UDP mode, hence we need to create a TCP socket for sending client config
    if (*socketfd == -1)
    {
        *socketfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    if (*socketfd == -1 || create_connection(*socketfd, *addr_info) == -1)
    {
        clean_up(*socketfd, *addr_info, NULL);
        return -1;
    }
    
    // Serialize and send the client config structure
    ssize_t bytes_sent = send(*socketfd, (const char *) &client_conf, sizeof(client_config), 0);
    if (bytes_sent < 0) {
        perror("Failed to send client configuration");
        return -1;
    }

    if (bytes_sent != sizeof(client_config)) {
        perror("Warning: Incomplete config sent to server\n");
        return -1;
    }

    return 0;
}

int send_data(input_client_config *config)
{
    InitializeSockets();

    int domain = AF_INET;
    int type = (strcmp("UDP", config->protocol) == 0) ? SOCK_DGRAM : SOCK_STREAM;
    int protocol = (strcmp("UDP", config->protocol) == 0) ? IPPROTO_UDP : IPPROTO_TCP;
    config->pktsize = (config->pktsize < 10) ? 10 : config->pktsize; // Minimum 10 bytes since we need the space to store sequence number and end_message
    
    // Step 1: Create socket that will be used to send data                 
    int socketfd = create_socket(domain, type, protocol);
    if (socketfd == -1)
    {
        return -1;
    }

    // Step 2: send the client config to the server
    struct addrinfo* addr_info = NULL;
    struct sockaddr local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    int mode = (strcmp("UDP", config->protocol) == 0) ? UDP_RECV : TCP_RECV;

    // late binding and early binding to acquire the info for local port number and ip
    socklen_t addr_len = sizeof(struct sockaddr);
    bind_socket(socketfd, 0, NULL); 
    if (getsockname(socketfd, (struct sockaddr *)&local_addr, &addr_len) == -1) 
    {
        perror("getsockname failed at recv_data");
        close(socketfd);
        return -1;
    }

    // reuse socketfd for sending client config if it is TCP connection
    int config_socketfd = (strcmp("UDP", config->protocol) == 0) ? -1 : socketfd;
    if (send_client_config(mode, config, &config_socketfd, &addr_info, &local_addr) == -1)
    {
        perror("fail to send client config to the server.\n");
        clean_up(socketfd, addr_info, NULL);
        return -1;
    }


    // For UDP send, we need the server port number and ip address
    // and then reset the socketfd and addrinfo for sending data
    server_config server_conf;
    if (strcmp(config->protocol, "UDP") == 0)
    {
        // if (recv(config_socketfd, (char *) &server_conf, sizeof(server_config), 0) <= 0)
        // {
        //     perror("Error receiving server config for UDP send\n");
        //     clean_up(socketfd, addr_info, NULL);
        //     return -1;
        // }
        char buffer[sizeof(server_config)];
        if (recv(config_socketfd, buffer, sizeof(server_config), 0) <= 0)
        {
            perror("Error receiving server config for UDP send\n");
            clean_up(socketfd, addr_info, NULL);
            return -1;
        }
        memcpy(&server_conf, buffer, sizeof(server_config));
        
        addr_info->ai_addr = (struct sockaddr *)&server_conf.server_addr;
        // printf("addr_info->ai_addrlen %d\n", addr_info->ai_addrlen);
        // printf("sizeof(server_conf.server_addr) %ld\n", sizeof(server_conf.server_addr));

        addr_info->ai_addrlen = sizeof(server_conf.server_addr);

        close(config_socketfd);
        // verify_server_address(addr_info->ai_addr);
    }

    // Step 2: Set the outgoing socket buffer size to sbufsize bytes
    if (config->sbufsize > 0)
    {
        if (setsockopt(socketfd, SOL_SOCKET, SO_SNDBUF, (const char *) &config->sbufsize, sizeof(config->sbufsize)) == -1) {
            perror("Error: setsockopt() failed to set send buffer size");
        }
    }

    // Step 3: Prepare dummy buffer to send
    char *buf = (char *)malloc(config->pktsize);
    memset(buf, 0, config->pktsize);

    // Step 4: prepare data structures for sending packets
    struct timeval start_time_packet, start_time_stats, current_time;
    long long total_elapsed_time = 0, curr_elapsed_time_packet = 0, curr_elapsed_time_stat;
    long long total_bytes_sent = 0;
    gettimeofday(&start_time_packet, NULL);  // Start timing for packet sending
    gettimeofday(&start_time_stats, NULL);   // Start timing for statistics

    double send_delay = 0; // In milliseconds
    if (config->pktrate != 0)
    {
        send_delay = (double)(config->pktsize)*1000/config->pktrate;
    }

    long packets_sequence = 1;
    long bytes_sent = 0;
    char last_message = 'E';

    // Step 5: send packet
    while (config->pktnum == 0 || packets_sequence <= config->pktnum)
    {
        // Adds the packet counter information into the packet
        memcpy(buf, &packets_sequence, sizeof(long));

        // Sent the char right after the packet_sequence to 'E' if this is the last packet
        (packets_sequence == config->pktnum) ? memcpy(buf+sizeof(long), &last_message, sizeof(char)) : 0;

        if (strcmp(config->protocol, "TCP") == 0)
        {
            // Send data using TCP
            bytes_sent = send_data_tcp(socketfd, buf, config->pktsize, 0);
        } 
        else
        {
            // Send data using UDP
            bytes_sent = send_data_udp(socketfd, buf, config->pktsize, 0, addr_info);
        }

        if (bytes_sent <= 0)
        {
            perror("Error: Failed to send packet");
            break;
        }

        total_bytes_sent += bytes_sent;
        
        // Calculate Statistic
        gettimeofday(&current_time, NULL);
        curr_elapsed_time_packet = (current_time.tv_sec - start_time_packet.tv_sec) * 1000 + (current_time.tv_usec - start_time_packet.tv_usec) / 1000;

        // Control packet rate
        if (curr_elapsed_time_packet < send_delay)
        {
            usleep((int)((send_delay - curr_elapsed_time_packet) * 1000)); 
        }
        gettimeofday(&start_time_packet, NULL);


        // Output statistics periodically
        gettimeofday(&current_time, NULL);
        curr_elapsed_time_stat = (current_time.tv_sec - start_time_stats.tv_sec) * 1000 +
                        (current_time.tv_usec - start_time_stats.tv_usec) / 1000;
        if (curr_elapsed_time_stat >= config->stat)
        {
            total_elapsed_time += curr_elapsed_time_stat;
            double rate_mbps = (total_bytes_sent * 8.0) / (total_elapsed_time * 1000.0);
            printf("Elapsed [%lldms] Pkts [%ld] Rate [%.2f Mbps]\n", total_elapsed_time, packets_sequence, rate_mbps);
            gettimeofday(&start_time_stats, NULL);
        }

        packets_sequence++;

    }

    // Step 6: clean up
    clean_up(socketfd, addr_info, buf);
    memset(&server_conf, 0, sizeof(server_conf)); // server_conf may contains invalid ptr
    return 0;
}

int recv_data(input_client_config *config)
{
    InitializeSockets();

    int domain = AF_INET;
    int type = (strcmp("UDP", config->protocol) == 0) ? SOCK_DGRAM : SOCK_STREAM;
    int protocol = (strcmp("UDP", config->protocol) == 0) ? IPPROTO_UDP : IPPROTO_TCP;
    config->pktsize = (config->pktsize < 10) ? 10 : config->pktsize; // Minimum 10 bytes since we need the space to store sequence number and end_message

    // Step 1: Create socket that will be used to receive data                 
    int socketfd = create_socket(domain, type, protocol);
    if (socketfd == -1)
    {
        return -1;
    }

    // Step 2: send the client config to the server
    struct addrinfo *addr_info = NULL;
    struct sockaddr local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    int mode = (strcmp("UDP", config->protocol) == 0) ? UDP_SEND : TCP_SEND;

    // late binding and early binding and acquire the info for local port number and ip
    socklen_t addr_len = sizeof(struct sockaddr);
    bind_socket(socketfd, 0, NULL); 
    if (getsockname(socketfd, (struct sockaddr *)&local_addr, &addr_len) == -1) 
    {
        perror("getsockname failed at recv_data");
        close(socketfd);
        return -1;
    }
    //verify_server_address(&local_addr);

    // reuse socketfd for sending client config if it is TCP connection
    int config_socketfd = (strcmp("UDP", config->protocol) == 0) ? -1 : socketfd;
    if (send_client_config(mode, config, &config_socketfd, &addr_info, &local_addr) == -1)
    {
        perror("Fail to send_client_config to server!\n");
        clean_up(socketfd, addr_info, NULL);
        return -1;
    }
    // close the config_socketfd since for UDP, we will not reuse it.
    if (strcmp("UDP", config->protocol) == 0)
    {
        close(config_socketfd);
    }

    // Step 3: Set the incoming socket buffer size to rbufsize bytes.
    if (config->rbufsize > 0)
    {
        if (setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, (const char *) &config->rbufsize, sizeof(config->rbufsize)) == -1)
        {
            perror("Error: setsockopt() failed to set receive buffer size");
        }
    }

    // Step 4: Prepare a buffer to receive the data
    char *buf = (char *)malloc(config->pktsize);

    // Step 5: Start receiving data
    struct sockaddr client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Initialize statistics
    /* For calculating Elapsed, Rate, and Jitter. */
    struct timeval start_time, current_time, last_packet_time;
    long long total_elapsed_time = 0;
    long packet_time_diff = 0, total_packet_time_diff = 0; 
    double total_jitter = 0.0;
    /* For calculating Pkts, Lost and Rate. */
    long packets_received = 0, packets_lost = 0, total_bytes_received = 0;
    long expected_sequence_num = 1;

    double MeanJitter = 0.0, MeanRecvItv = 0.0; long NumItv = 0; 

    gettimeofday(&start_time, NULL);
    last_packet_time = start_time;
    while (1) 
    {
        int bytes_received = 0;
        if (protocol == IPPROTO_TCP) 
        {
            // Receive data for TCP
            bytes_received = recv(socketfd, buf, config->pktsize, 0);
        } 
        else 
        {
            // Receive data for UDP
            // print_socket_info(socketfd);
            bytes_received = recvfrom(socketfd, buf, config->pktsize, 0, (struct sockaddr*)&client_addr, &client_addr_len);
        }
        
        if (bytes_received == 0) 
        {
            printf("Connection closed by peer.\n");
            break;
        }
        else if (bytes_received < 0)
        {
            perror("Error: recv() failed");
            break;
        }
        
        total_bytes_received += bytes_received;

        // Extract sequence number
        long received_sequence_num = *((long *)buf);

        // Check for packet loss
        if (received_sequence_num != 0)
        {
            // For TCP, we may receive fragemented packet. We can identify it by looking at the first 8 bytes of the packet buffer.
            // If received_sequence_num > expected_sequence_num, calculate the lost and reset the expected_sequence_num
            // If received_sequence_num = expected_sequence_num, not packet loss, increment the expected_sequence_num by 1
            // If received_sequence_num < expected_sequence_num, we skip the calculation on loss and expected_sequence_num
            if (received_sequence_num >= expected_sequence_num)
            {
                packets_lost += (received_sequence_num - expected_sequence_num);
                expected_sequence_num = received_sequence_num + 1;
            }

            packets_received++;
        }

        // Calculate the elapsed time for statistics printing
        gettimeofday(&current_time, NULL);
        long curr_elapsed_time = (current_time.tv_sec - start_time.tv_sec) * 1000 +
                                (current_time.tv_usec - start_time.tv_usec) / 1000;

        // Calculate Jitter
        if (received_sequence_num != 0) {
            // Calculate inter-packet time difference
            double RecvItv = (double)(current_time.tv_sec - last_packet_time.tv_sec) * 1000 +
                            (double)(current_time.tv_usec - last_packet_time.tv_usec) / 1000;
            last_packet_time = current_time;

            // Incremental jitter and mean interval calculation
            ++NumItv;
            if (NumItv > 1) {  // Only calculate after the first interval
                MeanJitter = (MeanJitter * (NumItv - 1) + fabs(RecvItv - MeanRecvItv)) / NumItv;
            }
            MeanRecvItv = (MeanRecvItv * (NumItv - 1) + RecvItv) / NumItv;
        }
        

        if (curr_elapsed_time >= config->stat)
        {
            total_elapsed_time += curr_elapsed_time;
            
            // Calculate throughput rate in Mbps
            double rate_mbps = (total_bytes_received * 8.0) / (total_elapsed_time * 1000.0);

            // Calculate packet loss percentage
            double loss_percentage = (packets_lost > 0) ? ((double)packets_lost / packets_received) * 100.0 : 0.0;

            // Print the statistics
            printf("Elapsed [%lldms] Pkts [%ld] Lost [%ld, %.2f%%] Rate [%.2f Mbps] Jitter [%.2f ms]\n",
                total_elapsed_time, packets_received, packets_lost, loss_percentage, rate_mbps, MeanJitter);
            
            // Reset start time for next interval
            gettimeofday(&start_time, NULL);
        }

        char end_message = *( (char*) (buf+sizeof(long)) );
        if (end_message == 'E')
        {
            printf("We have received all the packet, ending session now.\n");
            break;
        }
    }

    clean_up(socketfd, addr_info, buf);
    return 0;

}

int measure_response_time(input_client_config *config) {
    InitializeSockets();

    int domain = AF_INET;
    int type = (strcmp(config->protocol, "TCP") == 0)? SOCK_STREAM : SOCK_DGRAM;
    int protocol = (strcmp(config->protocol, "TCP") == 0) ? IPPROTO_TCP : IPPROTO_UDP;
    int mode = (strcmp("UDP", config->protocol) == 0) ? UDP_RESP : TCP_RESP;
    config->pktsize = (config->pktsize < 10) ? 10 : config->pktsize; // Minimum 10 bytes since we need the space to store sequence number and end_message

    // Step 1: Create socket that will be used to receive responded data from the server 
    int socketfd = create_socket(domain, type, protocol);
    if (socketfd == -1)
    {
        return -1;
    }

    // Step 2: send the client config to the server
    struct addrinfo *addr_info = NULL;
    struct sockaddr local_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    // late binding and early binding and acquire the info for local port number and ip
    socklen_t addr_len = sizeof(struct sockaddr);
    bind_socket(socketfd, 0, NULL); 
    if (getsockname(socketfd, (struct sockaddr *)&local_addr, &addr_len) == -1) 
    {
        perror("getsockname failed at recv_data");
        close(socketfd);
        return -1;
    }

    // reuse socketfd for sending client config if it is TCP connection
    int config_socketfd = (strcmp("UDP", config->protocol) == 0) ? -1 : socketfd;
    if (send_client_config(mode, config, &config_socketfd, &addr_info, &local_addr) == -1)
    {
        perror("Fail to send_client_config to server!\n");
        clean_up(socketfd, addr_info, NULL);
        return -1;
    }

    // For the case of UDP or TCP with non-persistence connection, we need the server port number and ip address
    // In UDP case, we need to know which destination port and ip to send UDP packet
    // In TCP non-presistence case, server will set up a new TCP socket for accpeting connections for this session, where the port will not be on 4180
    server_config server_conf;
    if (strcmp(config->protocol, "UDP") == 0 || (strcmp(config->protocol, "TCP") == 0 && !config->persist))
    {
        char buffer[sizeof(server_config)];
        if (recv(config_socketfd, buffer, sizeof(server_config), 0) <= 0)
        {
            perror("Error receiving server config for UDP send\n");
            clean_up(socketfd, addr_info, NULL);
            return -1;
        }
        memcpy(&server_conf, buffer, sizeof(server_config));
        
        addr_info->ai_addr = (struct sockaddr *)&server_conf.server_addr;
        addr_info->ai_addrlen = sizeof(server_conf.server_addr);
        // close(config_socketfd);
    }

    // Step 3: Set the incoming and outgoing socket buffer size to rbufsize bytes.
    // No need for TCP non-presistence case because we will set it later in the while loop below for each created socket
    if (!(strcmp(config->protocol, "TCP") == 0 && !config->persist)) 
    {
        set_socket_buffer_sizes(socketfd, config->sbufsize, config->rbufsize);
    }

    // Step 4: Prepare a buffer to send and receive the data
    char *send_buf = (char *)malloc(config->pktsize);
    memset(send_buf, 0, config->pktsize);
    char *recv_buf = (char *)malloc(config->pktsize);
    memset(recv_buf, 0, config->pktsize);

    // Step 3: Response time measurement loop
    struct timeval start_time, interval_start_time, end_time;
    double min_time = INFINITY, max_time = -INFINITY, total_time = 0.0;
    double total_jitter = 0.0, previous_time = 0.0;
    long long total_elapsed_time = 0;

    long packets_sequence = 1;
    long bytes_sent = 0;
    char last_message = 'E';

    // Start timing for interval statistics
    gettimeofday(&start_time, NULL);
    interval_start_time = start_time;

    while (config->pktnum == 0 || packets_sequence <= config->pktnum) {

        // Adds the packet counter information into the packet
        memcpy(send_buf, &packets_sequence, sizeof(long));

        // Sent the char right after the packet_sequence to 'E' if this is the last request
        (packets_sequence == config->pktnum) ? memcpy(send_buf+sizeof(long), &last_message, sizeof(char)) : 0;

        // Non-persistent TCP mode: Create a new connection for each request
        if (strcmp(config->protocol, "TCP") == 0 && !config->persist) {
            socketfd = create_socket(domain, type, protocol);
            if (create_connection(socketfd, addr_info) == -1) {
                fprintf(stderr, "Failed to create connection in non-persistent mode\n");
                break;
            }
            set_socket_buffer_sizes(socketfd, config->sbufsize, config->rbufsize);
        }

        // Mark start time
        gettimeofday(&start_time, NULL);

        // Send minimal request message
        ssize_t bytes_sent = (protocol == IPPROTO_TCP) ?
                             send_data_tcp(socketfd, send_buf, config->pktsize, 0) :
                             send_data_udp(socketfd, send_buf, config->pktsize, 0, addr_info);
        if (bytes_sent <= 0) {
            perror("Error sending request message");
            break;
        }

        // Receive response message
        char response_message[config->pktsize];
        ssize_t bytes_received = (protocol == IPPROTO_TCP) ?
                                 recv(socketfd, recv_buf, config->pktsize, 0) :
                                 recvfrom(socketfd, recv_buf, config->pktsize, 0, NULL, NULL);
        if (bytes_received <= 0) {
            perror("Error receiving response message");
            break;
        }

        // Mark end time and calculate response time
        gettimeofday(&end_time, NULL);
        double response_time = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                               (end_time.tv_usec - start_time.tv_usec) / 1000.0;

        // Update statistics
        total_time += response_time;
        if (response_time < min_time) min_time = response_time;
        if (response_time > max_time) max_time = response_time;

        // Calculate jitter
        if (packets_sequence > 0) {  // Calculate jitter only after the first packet
            double jitter = fabs(response_time - previous_time);
            total_jitter += jitter;
        }
        previous_time = response_time;

        // Interval statistics output
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        long long curr_elapsed_time = (current_time.tv_sec - interval_start_time.tv_sec) * 1000 + (current_time.tv_usec - interval_start_time.tv_usec) / 1000;

        if (curr_elapsed_time >= config->stat) {
            total_elapsed_time += curr_elapsed_time;
            double rate_mbps = (packets_sequence * config->pktsize * 8.0) / (total_elapsed_time * 1000.0);
            double mean_response_time = total_time / packets_sequence;
            double mean_jitter = packets_sequence > 1 ? total_jitter / (packets_sequence - 1) : 0.0;

            // Print statistics
            printf("Elapsed [%lldms] Pkts [%ld] Rate [%.2f Mbps] Mean Response Time [%.2f ms] Min [%.2f ms] Max [%.2f ms] Jitter [%.2f ms]\n",
                   total_elapsed_time, packets_sequence, rate_mbps, mean_response_time, min_time, max_time, mean_jitter);
            // Reset interval timer
            gettimeofday(&interval_start_time, NULL);
        }

        // Close the connection if in non-persistent TCP mode
        if (strcmp(config->protocol, "TCP") == 0 && !config->persist) {
            close(socketfd);
        }

        packets_sequence++;

        // Control request rate
        if (config->pktrate > 0) {
            usleep(1000000 / config->pktrate);  // Request rate in requests per second
        }
    }

    // Clean up
    if (config->persist && strcmp(config->protocol, "TCP") == 0) {
        close(socketfd);  // Close the persistent connection if still open
    }
    clean_up(config_socketfd, addr_info, NULL);
    free(send_buf);
    free(recv_buf);
    memset(&server_conf, 0, sizeof(server_conf)); // server_conf may contains invalid ptr
    return 0;
}

int send_data_http(input_client_config *config)
{

    InitializeSockets();

    // Step 1: Resolve the remote server address from config->url
    struct addrinfo hints, *res;
    struct sockaddr server_addr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    if (strcmp(config->protocol, "TCP") == 0) {
        hints.ai_socktype = SOCK_STREAM;
    } else if (strcmp(config->protocol, "UDP") == 0) {
        hints.ai_socktype = SOCK_DGRAM;
    } else {
        fprintf(stderr, "Unsupported protocol at send_data_http(): %s\n", config->protocol);
        return -1;
    }

    // Resolve the server address
    char *hostname = NULL;
    char *port = NULL;
    char *path = NULL;
    if (parse_url(config->url, &hostname, &port, &path) != 0) {
        fprintf(stderr, "Failed to parse URL: %s\n", config->url);
        return -1;
    }
    if (getaddrinfo(hostname, config->rport, &hints, &res) != 0) {
        perror("Failed to resolve server address");
        return -1;
    }
    server_addr = *res->ai_addr;

    // Step 2: Create the socket based on the protocol
    int socketfd = create_socket(res->ai_family, res->ai_socktype, (strcmp(config->protocol, "TCP") == 0) ? IPPROTO_TCP : IPPROTO_UDP);
    if (socketfd == -1) {
        freeaddrinfo(res);
        return -1;
    }

    // Step 3: Connect to the server, if using TCP
    if (strcmp(config->protocol, "TCP") == 0) {
        if (connect(socketfd, res->ai_addr, res->ai_addrlen) < 0) {
            perror("TCP connection failed");
            freeaddrinfo(res);
            close(socketfd);
            return -1;
        }
    }

    // Step 4: Prepare the HTTP GET request
    char http_request[8192];
    snprintf(http_request, sizeof(http_request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: NetProbeClient/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n",
            path, hostname);

// Debug: Print the constructed HTTP request
printf("Constructed HTTP Request:\n%s\n", http_request);
    if (http_request == NULL) {
        perror("Failed to create HTTP request");
        close(socketfd);
        return -1;
    }

    // Step 5: Send the HTTP GET request
    ssize_t bytes_sent = (strcmp(config->protocol, "TCP") == 0) ? 
                         send(socketfd, http_request, strlen(http_request), 0) : 
                         sendto(socketfd, http_request, strlen(http_request), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

    if (bytes_sent < 0) {
        perror("Failed to send HTTP request");
        freeaddrinfo(res);
        close(socketfd);
        return -1;
    }

    // Initialization
    char buffer[8192];  // Buffer to store the server response
    int bytes_received;
    FILE *file = NULL;

    // Open file if specified
    if (config->file != NULL && strcmp(config->file, "/dev/null") != 0) {
        file = fopen(config->file, "w");
        if (file == NULL) {
            perror("Failed to open file for saving response");
            close(socketfd);
            return -1;
        }
    }

    int header_ended = 0;  // Flag to detect the end of the HTTP headers
    char *header_buffer = (char *)malloc(8192);
    char *body_buffer = (char *)malloc(8192);  // Buffer for storing the body
    int header_buffer_size = 8192;
    int body_buffer_size = 8192;
    int header_length = 0;
    int body_length = 0;

    // Initialize header_buffer
    header_buffer[0] = '\0';

    if (strcmp(config->protocol, "TCP") == 0) {
        // TCP: Receive response in chunks
        while ((bytes_received = recv(socketfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes_received] = '\0';  // Null-terminate the received data

            if (!header_ended) {
                // Append buffer to header_buffer
                if (header_length + bytes_received >= header_buffer_size) {
                    // Reallocate header_buffer
                    header_buffer_size *= 2;
                    header_buffer = (char *)realloc(header_buffer, header_buffer_size);
                    if (header_buffer == NULL) {
                        perror("Failed to reallocate header buffer");
                        close(socketfd);
                        return -1;
                    }
                }
                strcat(header_buffer, buffer);
                header_length += bytes_received;

                // Search for end of headers
                char *header_end = strstr(header_buffer, "\r\n\r\n");
                if (header_end != NULL) {
                    // Headers ended
                    header_ended = 1;
                    int header_size = header_end - header_buffer + 4; // Include the "\r\n\r\n"
                    // Print header
                    printf("%.*s\n", header_size, header_buffer);

                    // Handle body data
                    int body_data_size = header_length - header_size;
                    if (body_data_size > 0) {
                        if (file != NULL) {
                            fwrite(header_end + 4, sizeof(char), body_data_size, file);
                        } else {
                            // Accumulate body data
                            if (body_length + body_data_size >= body_buffer_size) {
                                // Reallocate body_buffer
                                body_buffer_size *= 2;
                                body_buffer = (char *)realloc(body_buffer, body_buffer_size);
                                if (body_buffer == NULL) {
                                    perror("Failed to reallocate body buffer");
                                    close(socketfd);
                                    return -1;
                                }
                            }
                            memcpy(body_buffer + body_length, header_end + 4, body_data_size);
                            body_length += body_data_size;
                        }
                    }
                }
            } else {
                // Header has ended; handle body data
                if (file != NULL) {
                    fwrite(buffer, sizeof(char), bytes_received, file);
                } else {
                    if (body_length + bytes_received >= body_buffer_size) {
                        // Reallocate body_buffer
                        body_buffer_size *= 2;
                        body_buffer = (char *)realloc(body_buffer, body_buffer_size);
                        if (body_buffer == NULL) {
                            perror("Failed to reallocate body buffer");
                            close(socketfd);
                            return -1;
                        }
                    }
                    memcpy(body_buffer + body_length, buffer, bytes_received);
                    body_length += bytes_received;
                }
            }
        }
    }

    else if (strcmp(config->protocol, "UDP") == 0) {
        // UDP: Receive the response in a single packet
        bytes_received = recvfrom(socketfd, buffer, sizeof(buffer) - 1, 0, NULL, NULL);
        if (bytes_received < 0) {
            perror("Failed to receive UDP response");
            freeaddrinfo(res);
            free(header_buffer);
            free(body_buffer);
            close(socketfd);
            return -1;
        }

        buffer[bytes_received] = '\0';  // Null-terminate the received data

        // Process HTTP header and body
        char *header_end = strstr(buffer, "\r\n\r\n");
        if (header_end != NULL) {
            *header_end = '\0';  // Null-terminate the header

            // Print the header to stdout
            printf("%s\n", buffer);

            // If saving to a file, write the body (excluding header) to the file
            if (file != NULL) {
                fwrite(header_end + 4, sizeof(char), bytes_received - (header_end - buffer) - 4, file);
            } else {
                // Print the body to stdout
                printf("%s", header_end + 4);
            }
        } else {
            fprintf(stderr, "Error: HTTP response header not found in UDP packet.\n");
            freeaddrinfo(res);
            free(header_buffer);
            free(body_buffer);
            close(socketfd);
            return -1;
        }
    }

    // After the loop, if not saving to file, print the body
    if (file == NULL && body_length > 0) {
        printf("%.*s", body_length, body_buffer);
    }

    // Step 7: Clean up
    freeaddrinfo(res);
    free(header_buffer);
    free(body_buffer);
    if (file != NULL) {
        fclose(file);
    }
    close(socketfd);
    return 0;
}


int send_data_https(input_client_config *config)
{
    InitializeSockets();

    // Parse the URL to extract hostname, port, and path
    char *hostname = NULL;
    char *port = NULL;
    char *path = NULL;

    if (parse_url(config->url, &hostname, &port, &path) != 0) {
        fprintf(stderr, "Failed to parse URL: %s\n", config->url);
        return -1;
    }

    // If port is not specified in the URL, use config->rport or default to "443" for HTTPS
    if (port == NULL) {
        if (config->rport != NULL) {
            port = strdup(config->rport);
        } else {
            port = strdup("443");
        }
    }

    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_client_method();  // Use TLS
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    // Set up the trust store
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Failed to load default CA certificates\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    // Load additional CA certificates from a file
     if (!SSL_CTX_load_verify_locations(ctx, "../certificate/rootCA.crt", NULL)) {
        fprintf(stderr, "Warning: Failed to load rootCA.crt for self-signed certificate verification\n");
        ERR_print_errors_fp(stderr);
    }

    // Create a new SSL connection state
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        perror("Unable to create SSL structure");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    // Resolve the server address
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // Use IPv4
    hints.ai_socktype = SOCK_STREAM;  // TCP

    int gai_result = getaddrinfo(hostname, port, &hints, &res);
    if (gai_result != 0) {
        fprintf(stderr, "Failed to resolve server address: %s\n", gai_strerror(gai_result));
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    // Create a socket and connect to the server
    int server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_fd < 0) {
        perror("Unable to create socket");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        freeaddrinfo(res);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    if (connect(server_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("Unable to connect to server");
        close(server_fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        freeaddrinfo(res);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    freeaddrinfo(res);  // No longer needed

    // Attach the SSL session to the socket descriptor
    SSL_set_fd(ssl, server_fd);

    // Set SNI (Server Name Indication)
    SSL_set_tlsext_host_name(ssl, hostname);

    // Perform the SSL/TLS handshake with the server
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "Failed to establish SSL connection\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(server_fd);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    // Verify the server's certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        fprintf(stderr, "Failed to get server's certificate\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(server_fd);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    // Display the certificate subject data
    printf("Retrieved the server's certificate from: %s\n", hostname);
    printf("Displaying the certificate subject data:\n");
    X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, 0);
    printf("\n");

    // Authenticate the server's certificate
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result == X509_V_OK) {
        printf("Successfully validated the server's certificate from: %s\n", hostname);
    } else {
        printf("Failed to validate the server's certificate: %ld\n", verify_result);
        // Optionally, you can decide to continue or abort here
    }

    // Perform hostname verification
    if (X509_check_host(cert, hostname, 0, 0, NULL) == 1) {
        printf("Successfully validated the server's hostname matched to: %s\n", hostname);
    } else {
        printf("Server's hostname validation failed: %s\n", hostname);
    }

    X509_free(cert);  // Free the certificate

    // Prepare the HTTP GET request using the extracted path
    char http_request[8192];
    snprintf(http_request, sizeof(http_request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: NetProbeClient/1.0\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n\r\n",
             path, hostname);

    // Send the HTTP GET request over the SSL connection
    int request_len = strlen(http_request);
    int bytes_written = SSL_write(ssl, http_request, request_len);
    if (bytes_written <= 0) {
        fprintf(stderr, "Failed to send HTTPS request\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(server_fd);
        free(hostname);
        free(port);
        free(path);
        return -1;
    }

    // Receive the response from the server
    FILE *file = NULL;
    if (config->file != NULL && strcmp(config->file, "/dev/null") != 0) {
        file = fopen(config->file, "w");
        if (file == NULL) {
            perror("Failed to open file for saving response");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(server_fd);
            free(hostname);
            free(port);
            free(path);
            return -1;
        }
    }

    char buffer[8192];
    int bytes_read;
    int header_ended = 0;
    std::string header_buffer;
    std::string body_buffer;

    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';

        if (!header_ended) {
            header_buffer.append(buffer, bytes_read);
            size_t header_end_pos = header_buffer.find("\r\n\r\n");
            if (header_end_pos != std::string::npos) {
                // Headers ended
                header_ended = 1;
                size_t body_start = header_end_pos + 4;
                // Print header
                std::string header = header_buffer.substr(0, header_end_pos + 4);
                std::cout << header;

                // Handle body data
                if (body_start < header_buffer.size()) {
                    std::string body_part = header_buffer.substr(body_start);
                    if (file != NULL) {
                        fwrite(body_part.data(), sizeof(char), body_part.size(), file);
                    } else {
                        body_buffer.append(body_part);
                    }
                }
            }
        } else {
            // Header has ended; handle body data
            if (file != NULL) {
                fwrite(buffer, sizeof(char), bytes_read, file);
            } else {
                body_buffer.append(buffer, bytes_read);
            }
        }
    }

    // After reading all data, print the body if not saving to file
    if (file == NULL && !body_buffer.empty()) {
        std::cout << body_buffer << std::endl;
    }

    // Clean up and close connections
    if (file != NULL) {
        fclose(file);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    free(hostname);
    free(port);
    free(path);

    return 0;
}

int resolve_hostname(host_config *config)
{
    const char *hostname = config->hostname;
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];
    int status;

    // Initialize hints
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;    // Either IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // Any type of socket stream

    // Resolve the hostname
    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "Error: getaddrinfo failed: %s\n", gai_strerror(status));
        return -1;
    }

    printf("DNS lookup results for %s:\n", hostname);

    // Loop through the results and convert IP addresses to string form
    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;

        if (p->ai_family == AF_INET)
        { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);

            // Convert the IP address to a string
            inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
            printf("IP adress : %s\n", ipstr);
        }
    }

    // Free the linked list
    freeaddrinfo(res);
    return 0;
}


int check_args(int argc, char *argv[])
{
    if (argc < 2)
    {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    // Error checking
    if (argc < 2) {
        perror("Must specify the mode as the first argument.");
        return 1;
    }

    // Parse mode
    if (strcmp(argv[1], "-send") == 0) 
    {
        input_client_config* config = parse_client_mode(--argc, ++argv, SEND);
        send_data(config);
        free(config);
    } 
    else if (strcmp(argv[1], "-recv") == 0) 
    {
        input_client_config* config = parse_client_mode(--argc, ++argv, RECV);
        recv_data(config);
        free(config);
    } 
    else if (strcmp(argv[1], "-response") == 0) 
    {
        input_client_config* config = parse_client_mode(--argc, ++argv, RESPONSE);
        measure_response_time(config);
        free(config);
    }
    else if (strcmp(argv[1], "-http") == 0) 
    {
        input_client_config* config = parse_client_mode(--argc, ++argv, HTTP);
        (config->mode == HTTP) ? send_data_http(config) : send_data_https(config);
        free(config);
    }
    else if (strcmp(argv[1], "-host") == 0) 
    {
        host_config* h_config = parse_host_mode(argc, argv);
        resolve_hostname(h_config);
        free(h_config);
    } 
    else 
    {
        perror("Invalid mode.\n");
        return 1;
    }
    

    return 0;
}
