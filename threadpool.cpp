
#include "helper.hpp"
#include "threadpool.hpp"

int count = 0;

void *handle_tcp_send(void *arg) {
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.tcp_clients)++;

    // Step 1: Prepare buffer to send data
    char *buf = (char *)malloc(client_conf.pktsize);
    memset(buf, 0, client_conf.pktsize);

    // Step 2: Set the outgoing socket buffer size to sbufsize bytes and TCP congestion control module
    if (server_conf.sbufsize > 0)
    {
        if (setsockopt(server_conf.tcp_connect_socketfd, SOL_SOCKET, SO_SNDBUF, &server_conf.sbufsize, sizeof(server_conf.sbufsize)) == -1) {
            perror("Error: setsockopt() failed to set send buffer size");
        }
    }
    set_tcp_congestion_control(server_conf.tcp_connect_socketfd, server_conf.tcpcca);

    // Step 3: Set up data structures for rate control and sequence numbers
    struct timeval start_time, current_time;
    long long curr_elapsed_time = 0;
    gettimeofday(&start_time, NULL);

    double send_delay = 0; // In milliseconds
    if (client_conf.pktrate != 0) {
        send_delay = (double)(client_conf.pktsize) * 1000 / client_conf.pktrate;
    }

    long packets_sequence = 1;
    long bytes_sent = 0;
    char last_message = 'E';

    // Step 4: Send packets with sequence numbers and rate control
    while (client_conf.pktnum == 0 || packets_sequence <= client_conf.pktnum) {
        // Adds the packet counter information into the packet
        memcpy(buf, &packets_sequence, sizeof(long));

        // Sent the char right after the packet_sequence to 'E' if this is the last packet
        if (packets_sequence == client_conf.pktnum) {
            memcpy(buf + sizeof(long), &last_message, sizeof(char));
        }

        // Send data using TCP
        bytes_sent = send_data_tcp(server_conf.tcp_connect_socketfd, buf, client_conf.pktsize, 0);
        if (bytes_sent < 0) {
            perror("Error: Failed to send TCP packet");
            break;
        }
        packets_sequence++;

        // Calculate elapsed time
        gettimeofday(&current_time, NULL);
        curr_elapsed_time = (current_time.tv_sec - start_time.tv_sec) * 1000 +
                            (current_time.tv_usec - start_time.tv_usec) / 1000;

        // Control packet rate
        if (curr_elapsed_time < send_delay) {
            usleep((int)((send_delay - curr_elapsed_time) * 1000));
        }
        gettimeofday(&start_time, NULL);  // Reset the timer for the next packet
    }

    (*server_conf.tcp_clients)--;

    // Cleanup
    clean_up(server_conf.tcp_connect_socketfd, NULL, buf);
    return NULL;
}
void *handle_tcp_recv(void *arg) {
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.tcp_clients)++;

    // Step 1: Prepare buffer to receive data
    char *buf = (char *)malloc(client_conf.pktsize);
    memset(buf, 0, client_conf.pktsize);

    // Step 2: Set the incoming socket buffer size to rbufsize bytes.
    if (server_conf.rbufsize > 0)
    {
        if (setsockopt(server_conf.tcp_connect_socketfd, SOL_SOCKET, SO_RCVBUF, &server_conf.rbufsize, sizeof(server_conf.rbufsize)) == -1)
        {
            perror("Error: setsockopt() failed to set receive buffer size");
        }
    }

    // Step 3: Receive data over TCP
    long packets_received = 0;
    long bytes_received = 0;

    while (1) {
        bytes_received = recv(server_conf.tcp_connect_socketfd, buf, client_conf.pktsize, 0);
        if (bytes_received == 0)
        {
            printf("Connection closed by client at TCP_RECV.\n");
            break;
        } 
        else if (bytes_received < 0)
        {
            perror("Error: TCP receive failed at TCP_RECV.");
            break;
        }

        // Extract sequence number from the packet
        long received_sequence_num = *((long *)buf);
        packets_received++;

        // Check for the end of transmission
        char end_message = *((char *)(buf + sizeof(long)));
        if (end_message == 'E') {
            break;
        }
    }

    (*server_conf.tcp_clients)--;

    // Cleanup
    clean_up(server_conf.tcp_connect_socketfd, NULL, buf);
    return NULL;
}

void *handle_tcp_resp(void *arg) {
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.tcp_clients)++;

    // Step 1: Prepare buffer for receiving and responding data
    char *recv_buf = (char *)malloc(client_conf.pktsize);
    char *send_buf = (char *)malloc(client_conf.pktsize);
    memset(recv_buf, 0, client_conf.pktsize);
    memset(send_buf, 0, client_conf.pktsize);

    // Step 2: Set the socket buffer sizes and TCP congestion control module
    if (server_conf.rbufsize > 0) {
        if (setsockopt(server_conf.tcp_connect_socketfd, SOL_SOCKET, SO_RCVBUF, &server_conf.rbufsize, sizeof(server_conf.rbufsize)) == -1) {
            perror("Error: setsockopt() failed to set receive buffer size");
        }
    }
    if (server_conf.sbufsize > 0) {
        if (setsockopt(server_conf.tcp_connect_socketfd, SOL_SOCKET, SO_SNDBUF, &server_conf.sbufsize, sizeof(server_conf.sbufsize)) == -1) {
            perror("Error: setsockopt() failed to set send buffer size");
        }
    }
    set_tcp_congestion_control(server_conf.tcp_connect_socketfd, server_conf.tcpcca);

    // Set up non-persistence control socket if specified
    int nonpers_control_socketfd = -1;
    if (!client_conf.persist) {
        nonpers_control_socketfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (nonpers_control_socketfd == -1) {
            perror("Failed to accept new connection in non-persistent mode");
            return NULL;
        }

        // Set TCP congestion control module
        set_tcp_congestion_control(nonpers_control_socketfd, server_conf.tcpcca);

        struct sockaddr local_addr;
        socklen_t addr_len = sizeof(local_addr);
        bind_socket(nonpers_control_socketfd, 0, (char *)"localhost");
        if (getsockname(nonpers_control_socketfd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
            perror("getsockname failed");
            close(nonpers_control_socketfd);
            return NULL;
        }
        // verify_server_address(&local_addr);
        server_conf.server_addr = (struct sockaddr)local_addr;

        // Inform client the port and ip address to send
        char *buf_send = (char *)malloc(sizeof(server_config));
        memcpy(buf_send, &server_conf, sizeof(server_config));

        if (send_data_tcp(server_conf.tcp_connect_socketfd, buf_send, sizeof(server_config), 0) <= 0)
        {
            perror("Error: Failed to send the server config packet at handle_udp_recv()");
            close(nonpers_control_socketfd);
            return NULL;
        }
        free(buf_send);

        if (listen(nonpers_control_socketfd, SOMAXCONN) == -1) {
            perror("Failed to listen on control socket");
            close(nonpers_control_socketfd);
            return NULL;
        }
    }

    int communication_socket = server_conf.tcp_connect_socketfd;
    int expected_sequence_num = 1;
    while (1) {
        // In non-persistence mode, server will listen & accpet the new connection from the client
        if (!client_conf.persist) {
            communication_socket = accept(nonpers_control_socketfd, NULL, NULL);
            set_tcp_congestion_control(communication_socket, server_conf.tcpcca);
        }

        // Step 3: Receive request from the client
        ssize_t bytes_received = recv(communication_socket, recv_buf, client_conf.pktsize, 0);
        if (bytes_received <= 0) {
            perror("Error: Failed to receive data in TCP_RESP");
            if (!client_conf.persist) close(communication_socket);
            break;
        }

        // Extract sequence number
        long received_sequence_num = *((long *)recv_buf);

        // Check for packet loss
        if (received_sequence_num != 0)
        {
            // For TCP, we may receive fragemented packet. We can identify it by looking at the first 8 bytes of the packet buffer.
            // If received_sequence_num > expected_sequence_num, there are some packet lost, in this case we only reponsd to the most recently recived packet
            // If received_sequence_num = expected_sequence_num, not packet loss, increment the expected_sequence_num by 1
            // If received_sequence_num < expected_sequence_num, we skip this packet
            if (received_sequence_num >= expected_sequence_num)
            {
                // Step 4: Send response back to client containing the received sequence number
                memcpy(send_buf, &received_sequence_num, sizeof(long));
                ssize_t bytes_sent = send_data_tcp(communication_socket, send_buf, client_conf.pktsize, 0);
                if (bytes_sent <= 0) {
                    perror("Error: Failed to send response in TCP_RESP");
                    if (!client_conf.persist) close(communication_socket);
                    break;
                }
                expected_sequence_num = received_sequence_num + 1;
            }
            // else we do nothing
        }

        // Close the socket for non-persistent mode after each request-response cycle
        if (!client_conf.persist) {
            close(communication_socket);
        }

        // Check for the end of transmission
        char end_message = *((char *)(recv_buf + sizeof(long)));
        if (end_message == 'E') {
            break;
        }
    }

    (*server_conf.tcp_clients)--;

    // Step 6: Clean up
    free(recv_buf);
    free(send_buf);
    if (!client_conf.persist) {
            
        close(nonpers_control_socketfd);
    }
    return NULL;
}

void *handle_tcp_http(void *arg) {
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.tcp_clients)++;

    char buffer[8192];
    int bytes_received = recv(server_conf.tcp_connect_socketfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        // Error or client disconnected
        close(server_conf.tcp_connect_socketfd);
        (*server_conf.tcp_clients)--;
        return NULL;
    }
    buffer[bytes_received] = '\0';

    // Process HTTP request (simplified)
    // For now, send a simple HTTP response
    // We add trailing 0 to increase the size of the reponse packet to measure the performance of http reponse rate
    const char* http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, TCP HTTP client!\n";
    char rbuffer[1000];
    memset(rbuffer, 'A', sizeof(rbuffer));
    memcpy(rbuffer, http_response, strlen(http_response));
    // send(server_conf.tcp_connect_socketfd, http_response, strlen(http_response), 0);
    send(server_conf.tcp_connect_socketfd, rbuffer, sizeof(rbuffer), 0);

    close(server_conf.tcp_connect_socketfd);
    (*server_conf.tcp_clients)--;

    return NULL;
}

void* handle_tcp_https(void* arg) {
    global_config* config = (global_config*)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.tcp_clients)++;

    SSL* ssl = SSL_new(server_conf.ssl_ctx);
    if (!ssl) {
        perror("Unable to create SSL structure");
        ERR_print_errors_fp(stderr);
        close(server_conf.tcp_connect_socketfd);
        (*server_conf.tcp_clients)--;
        return NULL;
    }

    SSL_set_fd(ssl, server_conf.tcp_connect_socketfd);

    // Perform SSL/TLS handshake with client
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(server_conf.tcp_connect_socketfd);
        (*server_conf.tcp_clients)--;
        return NULL;
    }

    // Read HTTP request from client over SSL
    char buffer[8192];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        // Error or client disconnected
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server_conf.tcp_connect_socketfd);
        (*server_conf.tcp_clients)--;
        return NULL;
    }
    buffer[bytes_received] = '\0';

    // Process HTTP request (simplified)
    // For now, send a simple HTTP response over SSL
    // We add trailing 0 to increase the size of the reponse packet to measure the performance of https reponse rate
    const char* http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, TCP HTTPS client!\n";
    int response_len = strlen(http_response);
    char rbuffer[1000];
    memset(rbuffer, 'A', sizeof(rbuffer));
    memcpy(rbuffer, http_response, strlen(http_response));
    int bytes_sent = SSL_write(ssl, rbuffer, sizeof(rbuffer));
    if (bytes_sent <= 0) {
        ERR_print_errors_fp(stderr);
    }

    // const char* http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, TCP HTTPS client!\n";
    // int response_len = strlen(http_response);
    // int bytes_sent = SSL_write(ssl, http_response, response_len);
    // if (bytes_sent <= 0) {
    //     ERR_print_errors_fp(stderr);
    // }

    // Shutdown SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_conf.tcp_connect_socketfd);
    (*server_conf.tcp_clients)--;


    return NULL;
}

void *handle_udp_send(void *arg) {
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.udp_clients)++;

    struct addrinfo *addr_info = (struct addrinfo *)malloc(sizeof(struct addrinfo));
    addr_info->ai_addr = (struct sockaddr *)(&(client_conf.client_addr));
    addr_info->ai_addrlen = sizeof(client_conf.client_addr);

    // Step 1: Create UDP socket
    int udp_socketfd = create_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Step 2: Set the outgoing socket buffer size to sbufsize bytes
    if (server_conf.sbufsize > 0)
    {
        if (setsockopt(udp_socketfd, SOL_SOCKET, SO_SNDBUF, &server_conf.sbufsize, sizeof(server_conf.sbufsize)) == -1) {
            perror("Error: setsockopt() failed to set send buffer size");
        }
    }

    // Step 3: Prepare buffer to send data
    char *buf = (char *)malloc(client_conf.pktsize);
    memset(buf, 0, client_conf.pktsize);

    // Step 4: Set up data structures for rate control and sequence numbers
    struct timeval start_time, current_time;
    long long curr_elapsed_time = 0;
    gettimeofday(&start_time, NULL);

    double send_delay = 0; // In milliseconds
    if (client_conf.pktrate != 0) {
        send_delay = (double)(client_conf.pktsize) * 1000 / client_conf.pktrate;
    }

    long packets_sequence = 1;
    long bytes_sent = 0;
    char last_message = 'E';

    // Step 5: Send packets with sequence numbers and rate control
    bind_socket(udp_socketfd, 0, (char *)"localhost");
    while (client_conf.pktnum == 0 || packets_sequence <= client_conf.pktnum) {
        // Adds the packet counter information into the packet
        memcpy(buf, &packets_sequence, sizeof(long));

        // Sent the char right after the packet_sequence to 'E' if this is the last packet
        if (packets_sequence == client_conf.pktnum) {
            memcpy(buf + sizeof(long), &last_message, sizeof(char));
        }

        // Send data using UDP
        //printf("server send data to client\n");
        // verify_server_address(addr_info->ai_addr);
        // print_socket_info(udp_socketfd);
        bytes_sent = send_data_udp(udp_socketfd, buf, client_conf.pktsize, 0, addr_info);
        //printf("server sent : %ld bytes\n", bytes_sent);
        packets_sequence++;

        // Calculate elapsed time
        gettimeofday(&current_time, NULL);
        curr_elapsed_time = (current_time.tv_sec - start_time.tv_sec) * 1000 +
                            (current_time.tv_usec - start_time.tv_usec) / 1000;

        // Control packet rate
        if (curr_elapsed_time < send_delay) {
            usleep((int)((send_delay - curr_elapsed_time) * 1000)); 
        }
        gettimeofday(&start_time, NULL);
    }

    (*server_conf.udp_clients)--;

    // Cleanup
    clean_up(udp_socketfd, addr_info, buf);
    return NULL;
}

void *handle_udp_recv(void *arg)
{
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;
    socklen_t addr_len;

    (*server_conf.udp_clients)++;

    // Step 1: Create UDP socket
    int udp_socketfd = create_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Step 2: Set the incoming socket buffer size to rbufsize bytes.
    if (server_conf.rbufsize > 0)
    {
        if (setsockopt(udp_socketfd, SOL_SOCKET, SO_RCVBUF, &server_conf.rbufsize, sizeof(server_conf.rbufsize)) == -1)
        {
            perror("Error: setsockopt() failed to set receive buffer size");
        }
    }
    if (server_conf.sbufsize > 0)
    {
        if (setsockopt(udp_socketfd, SOL_SOCKET, SO_SNDBUF, &server_conf.sbufsize, sizeof(server_conf.sbufsize)) == -1) {
            perror("Error: setsockopt() failed to set send buffer size");
        }
    }

    // Step 3: Perform late binding and early binding
    struct sockaddr local_addr;
    addr_len = sizeof(local_addr);
    bind_socket(udp_socketfd, 0, (char *)"localhost");
    if (getsockname(udp_socketfd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
        perror("getsockname failed");
        close(udp_socketfd);
        return NULL;
    }
    // verify_server_address(&local_addr);
    server_conf.server_addr = (struct sockaddr)local_addr;

    // Step 4: Inform client the port and ip address to send
    char *buf_send = (char *)malloc(sizeof(server_config));
    memcpy(buf_send, &server_conf, sizeof(server_config));

    if (send_data_tcp(server_conf.tcp_connect_socketfd, buf_send, sizeof(server_config), 0) <= 0)
    {
        perror("Error: Failed to send the server config packet at handle_udp_recv()");
        close(udp_socketfd);
        return NULL;
    }
    free(buf_send);

    // Step 5: Prepare buffer to receive data
    char *buf_recv = (char *)malloc(client_conf.pktsize);
    addr_len = sizeof(client_conf.client_addr);

    // Step 5: Receive data over UDP
    long packets_received = 0;
    long bytes_received = 0;
    while (1) {
        bytes_received = recvfrom(udp_socketfd, buf_recv, client_conf.pktsize, 0, 
                                  (struct sockaddr*)&client_conf.client_addr, &addr_len);
        if (bytes_received <= 0) {
            perror("UDP receive error");
            break;
        }

        // Extract sequence number from the packet
        long received_sequence_num = *((long *)buf_recv);
        packets_received++;

        // Check for the end of transmission
        char end_message = *((char*)(buf_recv + sizeof(long)));
        if (end_message == 'E') {
            break;
        }
    }

    (*server_conf.udp_clients)--;

    // Cleanup
    clean_up(udp_socketfd, NULL, buf_recv);
    return NULL;
}

void *handle_udp_resp(void *arg) {
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.udp_clients)++;

    // Extract client addrinfo
    struct addrinfo *addr_info = (struct addrinfo *)malloc(sizeof(struct addrinfo));
    addr_info->ai_addr = (struct sockaddr *)(&(client_conf.client_addr));
    addr_info->ai_addrlen = sizeof(client_conf.client_addr);

    // Step 1: Create UDP socket for communication with the client
    int udp_socketfd = create_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Step 2: Set socket buffer sizes if specified
    if (server_conf.rbufsize > 0) {
        if (setsockopt(udp_socketfd, SOL_SOCKET, SO_RCVBUF, &server_conf.rbufsize, sizeof(server_conf.rbufsize)) == -1) {
            perror("Error: setsockopt() failed to set receive buffer size");
        }
    }
    if (server_conf.sbufsize > 0) {
        if (setsockopt(udp_socketfd, SOL_SOCKET, SO_SNDBUF, &server_conf.sbufsize, sizeof(server_conf.sbufsize)) == -1) {
            perror("Error: setsockopt() failed to set send buffer size");
        }
    }

    // Step 3: Bind UDP socket and get the assigned local IP and port number
    bind_socket(udp_socketfd, 0, (char *)"localhost");
    struct sockaddr local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(udp_socketfd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
        perror("Error: getsockname failed to retrieve local address for UDP socket");
        close(udp_socketfd);
        return NULL;
    }
    server_conf.server_addr = local_addr;  // Save local address in server config

    // Step 4: Send server’s UDP address to client over TCP
    char *send_conf_buf = (char *)malloc(sizeof(server_config));
    memcpy(send_conf_buf, &server_conf, sizeof(server_config));
    if (send_data_tcp(server_conf.tcp_connect_socketfd, send_conf_buf, sizeof(server_config), 0) <= 0) {
        perror("Error: Failed to send server UDP address to client");
        close(udp_socketfd);
        free(send_conf_buf);
        return NULL;
    }
    free(send_conf_buf);

    // Step 5: Prepare buffers for receiving and responding to data
    char *recv_buf = (char *)malloc(client_conf.pktsize);
    char *send_buf = (char *)malloc(client_conf.pktsize);
    memset(recv_buf, 0, client_conf.pktsize);
    memset(send_buf, 0, client_conf.pktsize);
    socklen_t client_addr_len = sizeof(client_conf.client_addr);

    // Step 6: Start the request-response loop over UDP
    while (1) {
        // Receive data from the client
        ssize_t bytes_received = recvfrom(udp_socketfd, recv_buf, client_conf.pktsize, 0,
                                          (struct sockaddr *)&client_conf.client_addr, &client_addr_len);
        if (bytes_received <= 0) {
            perror("Error: Failed to receive UDP data from client");
            break;
        }

        // Send the response back to the client's UDP address
        ssize_t bytes_sent = send_data_udp(udp_socketfd, send_buf, client_conf.pktsize, 0, addr_info);
        if (bytes_sent <= 0) {
            perror("Error: Failed to send UDP response to client");
            break;
        }

        // Check for the end of transmission indicated by a specific character, such as 'E'
        char end_message = *((char *)(recv_buf + sizeof(long)));
        if (end_message == 'E') {
            break;
        }
    }

    (*server_conf.udp_clients)--;

    // Step 7: Clean up
    clean_up(udp_socketfd, addr_info, NULL);
    free(recv_buf);
    free(send_buf);
    return NULL;
}

void *handle_udp_http(void *arg) {
    global_config *config = (global_config *)arg;
    client_config client_conf = config->client_conf;
    server_config server_conf = config->server_conf;

    (*server_conf.udp_clients)++;

    std::string http_response = "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 1024\r\n\r\n"
                                "Hello, UDP HTTP client!";

    int bytes_sent = sendto(server_conf.udp_recv_socketfd, http_response.c_str(), http_response.size(), 0, &client_conf.client_addr, sizeof(client_conf.client_addr));
    if(bytes_sent == -1)
    {
        perror("Fail to send UDP HTTP response.\n");
        return NULL;
    }

    (*server_conf.udp_clients)--;

    return NULL;
}


// ThreadPool Constructor
ThreadPool::ThreadPool(int initial_size) : pool_size(initial_size), active_threads(0), stop(false) {
    pthread_mutex_init(&lock, NULL);
    pthread_cond_init(&notify, NULL);

    // Start worker threads
    for (int i = 0; i < initial_size; ++i) {
        auto worker = std::make_unique<Thread>(this);
        worker->start();
        threads.push_back(std::move(worker));         // Move unique_ptr into the vector
    }

    // Start the pool manager thread
    pthread_create(&timer_thread, NULL, ThreadPool::manage_pool_size, (void *)this);
}

// ThreadPool Destructor
ThreadPool::~ThreadPool() {
    stop = true;
    pthread_cond_broadcast(&notify);

    // Join all worker threads
    for (auto &worker : threads) {
        if (!worker->should_terminate()) {
            pthread_join(worker->thread, NULL);
        }
    }

    pthread_join(timer_thread, NULL);
    pthread_mutex_destroy(&lock);
    pthread_cond_destroy(&notify);
}

// Manager thread function
void* ThreadPool::manage_pool_size(void *arg) {
    ThreadPool *pool = static_cast<ThreadPool*>(arg);
    auto shrink_start_time = std::chrono::steady_clock::time_point();
    bool shrink_timer_active = false;

    while (!pool->stop) {
        sleep(1); // check every one second

        pthread_mutex_lock(&pool->lock);
        int queue_size = pool->task_queue.size();
        int total_threads = pool->threads.size();
        int utilization = (pool->active_threads * 100) / total_threads;
        // printf("queue_size : %d, total_threads: %d, utilization: %d\n", queue_size, total_threads, utilization);

        if (utilization >= POOL_GROW_THRESHOLD) {

            int new_threads = total_threads;
            for (int i = 0; i < new_threads; ++i) {
                auto worker = std::make_unique<Thread>(pool);
                worker->start();
                pool->threads.push_back(std::move(worker));
            }

            pool->pool_size = pool->threads.size();
            shrink_timer_active = false;
        } else if (utilization < POOL_SHRINK_THRESHOLD) {
            if (!shrink_timer_active) {
                shrink_start_time = std::chrono::steady_clock::now();
                shrink_timer_active = true;
            } else {
                auto elapsed_time = std::chrono::steady_clock::now() - shrink_start_time;
                if (std::chrono::duration_cast<std::chrono::seconds>(elapsed_time).count() >= POOL_SHRINK_TIMEOUT) {
                    int threads_to_terminate = total_threads / 2;
                    for (int i = total_threads - threads_to_terminate; i < total_threads; ++i) {
                        pool->threads[i]->signal_terminate();
                    }

                    // Release the lock and boardcast, let the thread to terminate itself
                    pthread_mutex_unlock(&pool->lock);
                    pthread_cond_broadcast(&pool->notify);

                    // Wait for each thread to complete and remove it from the vector
                    for (int i = total_threads - threads_to_terminate; i < total_threads; ++i) {
                        pthread_join(pool->threads[i]->thread, NULL);
                    }

                    pthread_mutex_lock(&pool->lock);

                    pool->threads.resize(total_threads - threads_to_terminate);
                    pool->pool_size = pool->threads.size();
                    shrink_timer_active = false;
                }
            }
        } else {
            shrink_timer_active = false;
        }

        pthread_mutex_unlock(&pool->lock);
    }
    return NULL;
}

void ThreadPool::add_task(Task &&new_task) {
    pthread_mutex_lock(&lock);
    task_queue.push(std::move(new_task));
    pthread_cond_signal(&notify);
    pthread_mutex_unlock(&lock);
    // printf("add task success\n");
}

// Thread constructor
Thread::Thread(ThreadPool *pool) : is_terminate(false), pool(pool) {}

// Signal the thread to terminate
void Thread::signal_terminate() {
    is_terminate.store(true, std::memory_order_relaxed);
}

// Check if the thread should terminate
bool Thread::should_terminate() const {
    return is_terminate.load(std::memory_order_relaxed);
}

// Start the thread
void Thread::start() {
    pthread_create(&thread, NULL, &Thread::start_routine, this);
}

// Worker thread function
void Thread::run() {
    while (1) {
        pthread_mutex_lock(&pool->lock);

        while ((pool->task_queue.empty() && !pool->stop && !should_terminate())) {
            pthread_cond_wait(&pool->notify, &pool->lock);
        }

        if (pool->stop || should_terminate()) {
            // printf("Thread terminate itself.\n");
            pthread_mutex_unlock(&pool->lock);
            pthread_exit(NULL);
        }

        if (!pool->task_queue.empty()) {
            Task task = std::move(pool->task_queue.front());
            pool->task_queue.pop();
            pool->active_threads++;
            pthread_mutex_unlock(&pool->lock);

            count++;
            // printf("task number: %d\n", count);
            handle_task(&task.config);

            pthread_mutex_lock(&pool->lock);
            pool->active_threads--;
            pthread_mutex_unlock(&pool->lock);
        } else {
            pthread_mutex_unlock(&pool->lock);
        }
    }
}

// Static helper to start the thread routine
void* Thread::start_routine(void* arg) {
    static_cast<Thread*>(arg)->run();
    return NULL;
}

// Task handling function based on mode
void handle_task(global_config *global_conf) {
    switch (global_conf->client_conf.mode) {
        case TCP_SEND:
            handle_tcp_send(global_conf);
            break;
        case TCP_RECV:
            handle_tcp_recv(global_conf);
            break;
        case TCP_RESP:
            handle_tcp_resp(global_conf);
            break;
        case TCP_HTTP:
            handle_tcp_http(global_conf);
            break;
        case TCP_HTTPS:
            handle_tcp_https(global_conf);
            break;
        case UDP_SEND:
            handle_udp_send(global_conf);
            break;
        case UDP_RECV:
            handle_udp_recv(global_conf);
            break;
        case UDP_RESP:
            handle_udp_resp(global_conf);
            break;
        case UDP_HTTP:
            handle_udp_http(global_conf);
            break;
        default:
            perror("Unknown request mode from client");
    }
}