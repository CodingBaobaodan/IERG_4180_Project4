#include "helper.hpp"
#include "threadpool.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

extern "C" 
{
    #include <pthread.h>
}

// This config is not the final server_config we defined in helper.h
// It is configurated from the command line and contribute to the final server_config
typedef struct input_server_config
{
    char *lhost = nullptr;
    char *tcpcca = nullptr;
    char *protocol = nullptr;
    int stat = 0;
    int sbufsize = 0;
    int rbufsize = 0;
    int poolsize = 0;
    unsigned short lport = 0;
    unsigned short lhttpport = 0;
    unsigned short lhttpsport = 0;
    unsigned short shutdownport = 0;

    // Socket file descriptors
    int SuperNetProbe_socketfd = -1;
    int UltraNetProbe_http_tcp_socketfd = -1;
    int UltraNetProbe_http_udp_socketfd = -1;
    int UltraNetProbe_https_tcp_socketfd = -1;
    int shutdown_socketfd = -1; // New shutdown socket
} input_server_config;

// Function to periodically print statistics
void print_statistics(input_server_config* config, const ThreadPool &pool, std::atomic<int>& tcp_clients, std::atomic<int>& udp_clients, std::chrono::steady_clock::time_point start_time, std::atomic<bool>& running)
{
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config->stat));
        
        auto current_time = std::chrono::steady_clock::now();
        int elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();

        std::cout << "Elapsed [" << elapsed_seconds << "s] "
              << "ThreadPool [" << pool.pool_size << "|" << pool.active_threads << "] "
              << "TCP Clients [" << tcp_clients << "] "
              << "UDP Clients [" << udp_clients << "]" << std::endl;
    }
}

// Function to print connected client info
void print_connection_info(struct sockaddr client_addr, global_config *global_conf)
{
    if (client_addr.sa_family != AF_INET) {
        printf("Error: Invalid address family. Expecting IPv4.\n");
        return;
    }

    struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_addr;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr_in->sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(addr_in->sin_port);

    const char *mode_str = "Invalid mode";
    const char *proto_str = "Invalid protocol";
    if (global_conf->client_conf.mode == TCP_SEND || global_conf->client_conf.mode == UDP_SEND) {
        mode_str = "SEND";
    } else if (global_conf->client_conf.mode == TCP_RECV || global_conf->client_conf.mode == UDP_RECV) {
        mode_str = "RECV";
    } else if (global_conf->client_conf.mode == TCP_RESP|| global_conf->client_conf.mode == UDP_RESP) {
        mode_str = "RESP";
    }
    
    if (global_conf->client_conf.mode == TCP_SEND || global_conf->client_conf.mode == TCP_RECV || global_conf->client_conf.mode == TCP_RESP) {
        proto_str = "TCP";
    } else if (global_conf->client_conf.mode == UDP_SEND || global_conf->client_conf.mode == UDP_RECV || global_conf->client_conf.mode == UDP_RESP) {
        proto_str = "UDP";
    }

    printf("Connected to %s port %d, %s, %s, %.2f Bps\n",
           client_ip,
           client_port,
           mode_str,
           proto_str,
           (double)global_conf->client_conf.pktrate);
}


input_server_config* parse_server_mode(int argc, char *argv[])
{
    // Allocate memory for server configuration
    input_server_config *config = (input_server_config *)malloc(sizeof(struct input_server_config));
    if (!config) {
        perror("Failed to allocate memory for server_config\n");
        exit(-1);
    }

    // Set default values
    config->stat = 500;
    config->lhost = NULL;
    config->lport = 4180;
    config->lhttpport = 4080;
    config->lhttpsport = 4081;
    config->shutdownport = 4082;
    config->sbufsize = 0;
    config->rbufsize = 0;
    config->tcpcca = NULL;
    config->protocol = my_strdup("UDP");
    config->poolsize = 8;

    // Define long options
    int option;
    static struct option long_options[] = {
        {"lhost", required_argument, 0, 'a'},
        {"lport", required_argument, 0, 'b'},
        {"sbufsize", required_argument, 0, 'c'},
        {"rbufsize", required_argument, 0, 'd'},
        {"tcpcca", required_argument, 0, 'e'},
        {"poolsize", required_argument, 0, 'f'},
        {"lhttpport", required_argument, 0, 'g'},
        {"lhttpsport", required_argument, 0, 'h'},
        {"stat", required_argument, 0, 'i'},
        {"proto", required_argument, 0, 'j'},
        {"shutdownport", required_argument, 0, 'k'},
        {0, 0, 0, 0}
    };

    // Parse the command line options
    while ((option = getopt_long_only(argc, argv, "", long_options, NULL)) != -1) {
        switch (option) {
            // -lhost
            case 'a':
                config->lhost = my_strdup(optarg);
                break;
            // -lport
            case 'b':
                config->lport = (unsigned short)atoi(optarg);
                break;
            // -sbufsize
            case 'c':
                config->sbufsize = atoi(optarg);
                break;
            // -rbufsize
            case 'd':
                config->rbufsize = atoi(optarg);
                break;
            // -tcpcca
            case 'e':
                config->tcpcca = my_strdup(optarg);
                break;
            // -poolsize
            case 'f':
                config->poolsize = atoi(optarg);
                if (config->poolsize <= 0) {
                    fprintf(stderr, "Error: poolsize must be greater than 0! \n");
                    exit(-1);
                }
                break;
            // -lhttpport
            case 'g':
                config->lhttpport = (unsigned short)atoi(optarg);
                break;
            // -lhttpsport
            case 'h':
                config->lhttpsport = (unsigned short)atoi(optarg);
                break;
            // -stat
            case 'i':
                config->stat = (int)atoi(optarg);
                break;
            // -proto
            case 'j':
                free(config->protocol);
                config->protocol = my_strdup(optarg);
                capitalize_string(config->protocol);
                break;
            // -shutdownport
            case 'k':
                config->shutdownport = (unsigned short)atoi(optarg);
                break;
            default:
                perror("Unknown option for server mode\n");
                exit(-1);
        }
    }

    // Log the configuration values
    printf("Server mode: stat=%d, lhost=%s, lport=%d, lhttpport=%d, lhttpsport=%d, shutdownport=%d, sbufsize=%d, rbufsize=%d, proto=%s\n",
           config->stat, config->lhost ? config->lhost : "INADDR_ANY", config->lport, config->lhttpport, config->lhttpsport, config->shutdownport, config->sbufsize, config->rbufsize, config->protocol);
    
    return config;
}

int receive_client_config(int client_socketfd, client_config *config)
{
    // Read the client's config data from TCP control connection
    int bytes_received = recv(client_socketfd, config, sizeof(client_config), 0);
    if (bytes_received <= 0) {
        perror("Failed to receive client config");
        return -1;
    }

    return 0;
}

// Start server function using the thread pool
int start_SuperNetProbe_server(input_server_config* config, ThreadPool &thread_pool, std::atomic<int> &tcp_clients, std::atomic<int> &udp_clients, std::atomic<bool> &running) {

    // Create control TCP socket for accepting client connections
    int control_socketfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind_socket(control_socketfd, config->lport, config->lhost) == -1) {
        close(control_socketfd);
        return -1;
    }
    set_tcp_congestion_control(control_socketfd, config->tcpcca);
    config->SuperNetProbe_socketfd = control_socketfd;

    if (listen(control_socketfd, SOMAXCONN) == -1) {
        perror("Failed to listen on control socket");
        close(control_socketfd);
        return -1;
    }
    printf("SuperNetProbe_server listening on port %d\n", config->lport);
    //printf("Binding local socket to port number %d with late binding ... successful\n", config->lport);
    //printf("Listening to incoming connection request ...\n");

    struct sockaddr client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (running) {
        // Accept incoming TCP control connection
        int client_socketfd = accept(control_socketfd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socketfd == -1) {
            if (!running) {
                // Shutdown initiated, exit loop
                break;
            }
            perror("Failed to accept incoming connection\n");
            continue;
        }

        if (!running) {
            close(client_socketfd);
            break;
        }

        // Verify and process client address
        //printf("1\n");
        //verify_server_address(&client_addr);

        // Receive client configuration
        client_config client_conf;
        if (receive_client_config(client_socketfd, &client_conf) == -1) {
            perror("Failed to receive client config.\n");
            close(client_socketfd);
            continue;
        }

        // Store necessary server-side configuration
        global_config global_conf;
        memset(&global_conf, 0, sizeof(global_config));
        global_conf.client_conf = client_conf;
        global_conf.server_conf.sbufsize = config->sbufsize;
        global_conf.server_conf.rbufsize = config->rbufsize;
        global_conf.server_conf.control_socketfd = control_socketfd;
        global_conf.server_conf.tcp_connect_socketfd = client_socketfd;
        global_conf.server_conf.tcpcca = config->tcpcca;
        global_conf.server_conf.tcp_clients = &tcp_clients;
        global_conf.server_conf.udp_clients = &udp_clients;
        // Get the internet address of client
        struct sockaddr_in *tmp1 = (struct sockaddr_in *)&global_conf.client_conf.client_addr;
        struct sockaddr_in *tmp2 = (struct sockaddr_in *)&client_addr;
        tmp1->sin_addr = tmp2->sin_addr;
        // print_connection_info(global_conf.client_conf.client_addr, &global_conf);

        // Create a task and add it to the thread pool
        Task task;
        task.config = global_conf;
        thread_pool.add_task(std::move(task));

    }

    // we close control socketfd at the shutdown_listener thread
    return 0;
}

void start_UltraNetProbe_http_tcp_server(input_server_config* config, ThreadPool &thread_pool, std::atomic<int>& tcp_clients, std::atomic<bool> &running)
{
    // Create socket for HTTP TCP connections
    int http_socketfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind_socket(http_socketfd, config->lhttpport, config->lhost) == -1) {
        close(http_socketfd);
        return;
    }
    config->UltraNetProbe_http_tcp_socketfd = http_socketfd;


    if (listen(http_socketfd, SOMAXCONN) == -1) {
        perror("Failed to listen on HTTP socket");
        close(http_socketfd);
        return;
    }
    printf("HTTP Server listening on port %d\n", config->lhttpport);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (running) {
        // Accept incoming HTTP TCP connection
        int client_socketfd = accept(http_socketfd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socketfd == -1) {
            if (!running) {
                // Shutdown initiated, exit loop
                break;
            }
            perror("Failed to accept HTTP connection");
            continue;
        }

        if (!running) {
            close(client_socketfd);
            break;
        }

        // Store necessary server-side configuration
        global_config global_conf;
        memset(&global_conf, 0, sizeof(global_config));
        global_conf.client_conf.mode = TCP_HTTP;
        global_conf.server_conf.tcp_connect_socketfd = client_socketfd;
        global_conf.server_conf.tcp_clients = &tcp_clients;

        // Create a task and add it to the thread pool
        Task task;
        task.config = global_conf;
        thread_pool.add_task(std::move(task));

        //printf("new connection with tcp number : %d", tcp_clients.load());

    }

    // We close http_socketfd at the shutdown_listener thread

}

void start_UltraNetProbe_http_udp_server(input_server_config* config, ThreadPool &thread_pool, std::atomic<int>& udp_clients, std::atomic<bool> &running)
{
    // Create socket for HTTP UDP connections
    int udp_socketfd = create_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socketfd == -1) {
        perror("Failed to create UDP socket");
        return;
    }
    config->UltraNetProbe_http_udp_socketfd = udp_socketfd;


    if (bind_socket(udp_socketfd, config->lhttpport, config->lhost) == -1) {
        perror("Failed to bind UDP socket");
        close(udp_socketfd);
        return;
    }
    printf("HTTP UDP Server listening on port %d\n", config->lhttpport);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (running) {
        // Receive data from client
        char buffer[8192];
        int bytes_received = recvfrom(udp_socketfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&client_addr, &addr_len);
        if (bytes_received <= 0) {
            if (!running) {
                // Shutdown initiated, exit loop
                break;
            }
            // Error or no data received
            perror("Failed to receive UDP data");
            continue;
        }

        if (!running) {
            break;
        }

        buffer[bytes_received] = '\0';  // Null-terminate the received data

        // Prepare the global configuration for the task
        global_config global_conf;
        memset(&global_conf, 0, sizeof(global_config));
        global_conf.client_conf.mode = UDP_HTTP; // Set the mode to UDP_HTTP
        global_conf.server_conf.udp_recv_socketfd = udp_socketfd; // Store the socket that will be used to send the data back 
        memcpy(&global_conf.client_conf.client_addr, &client_addr, sizeof(client_addr)); // Store the client address
        global_conf.server_conf.request = std::string(buffer, bytes_received); // Copy the received data to the config

        // Pass the udp_clients atomic variable
        global_conf.server_conf.udp_clients = &udp_clients;

        // Create a task and add it to the thread pool
        Task task;
        task.config = global_conf;
        thread_pool.add_task(std::move(task));
    }

    // We close udp_socketfd at the shutdown_listener thread

}


void start_UltraNetProbe_https_tcp_server(input_server_config* config, ThreadPool& thread_pool, std::atomic<int>& tcp_clients, std::atomic<bool> &running) {
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create SSL context
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return;
    }

    // Configure SSL context with certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "../certificate/domain.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "../certificate/domain.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    // Create socket for HTTPS TCP connections
    int https_socketfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind_socket(https_socketfd, config->lhttpsport, config->lhost) == -1) {
        close(https_socketfd);
        SSL_CTX_free(ctx);
        return;
    }
    config->UltraNetProbe_https_tcp_socketfd = https_socketfd;


    if (listen(https_socketfd, SOMAXCONN) == -1) {
        perror("Failed to listen on HTTPS socket");
        close(https_socketfd);
        SSL_CTX_free(ctx);
        return;
    }
    printf("HTTPS Server listening on port %d\n", config->lhttpsport);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (running) {
        // Accept incoming HTTPS TCP connection
        int client_socketfd = accept(https_socketfd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_socketfd == -1) {
            if (!running) {
                // Shutdown initiated, exit loop
                break;
            }
            perror("Failed to accept HTTPS connection");
            continue;
        }

        if (!running) {
            close(client_socketfd);
            break;
        }

        // Store necessary server-side configuration
        global_config global_conf;
        memset(&global_conf, 0, sizeof(global_config));
        global_conf.client_conf.mode = TCP_HTTPS;
        global_conf.server_conf.tcp_connect_socketfd = client_socketfd;
        global_conf.server_conf.tcp_clients = &tcp_clients;
        global_conf.server_conf.ssl_ctx = ctx; // Pass the SSL context

        // Create a task and add it to the thread pool
        Task task;
        task.config = global_conf;
        thread_pool.add_task(std::move(task));
    }

    // We close http_socketfd at the shutdown_listener thread
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

void start_shutdown_listener(input_server_config* config, std::atomic<bool>& running) {
    // Create shutdown TCP socket on port 4082
    int shutdown_socketfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    config->shutdown_socketfd = shutdown_socketfd; // Assign to config

    if (bind_socket(shutdown_socketfd, config->shutdownport, config->lhost) == -1) {
        close(shutdown_socketfd);
        printf("Failed to bind shutdown socket on port %d", config->shutdownport);
        return;
    }

    if (listen(shutdown_socketfd, 1) == -1) {
        perror("Failed to listen on shutdown socket");
        close(shutdown_socketfd);
        return;
    }
    printf("Shutdown Listener listening on port %d\n", config->shutdownport);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Accept only one connection for shutdown
    int client_socketfd = accept(shutdown_socketfd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_socketfd == -1) {
        perror("Failed to accept shutdown connection");
        close(shutdown_socketfd);
        return;
    }

    printf("Shutdown signal received. Initiating graceful shutdown...\n");
    running = false; // Signal to stop server threads

    // Close the shutdown socket to prevent further connections
    close(shutdown_socketfd);
    config->shutdown_socketfd = -1;

    /// Host for dummy connections
    const char* host = "127.0.0.1";

    // List of TCP ports to perform dummy connects
    std::vector<unsigned short> tcp_ports = {config->lport, config->lhttpport, config->lhttpsport};

    // Launch dummy connects in separate threads to prevent blocking
    std::vector<std::thread> dummy_threads;
    for (auto port : tcp_ports) {
        if (port != 0) { // Ensure port is valid
            dummy_threads.emplace_back(perform_dummy_tcp_connect, host, port);
        }
    }

    // Perform dummy UDP sendto to unblock recvfrom()
    if (config->UltraNetProbe_http_udp_socketfd != -1) {
        dummy_threads.emplace_back(perform_dummy_udp_sendto, host, config->lhttpport);
    }

    // Wait for all dummy connections to complete
    for (auto& th : dummy_threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    close(client_socketfd);
}

int main(int argc, char *argv[])
{
    // Parse server configuration
    input_server_config* config = parse_server_mode(argc, argv);

    // Initialize thread pool
    ThreadPool thread_pool(config->poolsize);

    // Initialize shared variables
    std::atomic<int> tcp_clients(0);
    std::atomic<int> udp_clients(0);
    std::atomic<bool> running(true);

    // Initialize start time for statistics
    auto start_time = std::chrono::steady_clock::now();

    // Create threads for each server functionality
    std::thread SuperNetProbe_server_thread(start_SuperNetProbe_server, config, std::ref(thread_pool), std::ref(tcp_clients), std::ref(udp_clients), std::ref(running));
    std::thread UltraNetProbe_http_tcp_thread(start_UltraNetProbe_http_tcp_server, config, std::ref(thread_pool), std::ref(tcp_clients), std::ref(running));
    std::thread UltraNetProbe_http_udp_thread(start_UltraNetProbe_http_udp_server, config, std::ref(thread_pool), std::ref(udp_clients), std::ref(running));
    std::thread UltraNetProbe_https_tcp_thread(start_UltraNetProbe_https_tcp_server, config, std::ref(thread_pool), std::ref(tcp_clients), std::ref(running));
    std::thread stats_thread(print_statistics, config, std::ref(thread_pool), std::ref(tcp_clients), std::ref(udp_clients), start_time, std::ref(running));

    // Start the shutdown listener thread
    std::thread shutdown_listener_thread(start_shutdown_listener, config, std::ref(running));

    // Join threads
    shutdown_listener_thread.join();
    SuperNetProbe_server_thread.join();
    UltraNetProbe_http_tcp_thread.join();
    UltraNetProbe_http_udp_thread.join();
    UltraNetProbe_https_tcp_thread.join();

    // Stop the stats thread
    stats_thread.join();

    return 0;
}


