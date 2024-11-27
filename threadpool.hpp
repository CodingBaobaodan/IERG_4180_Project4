#include <pthread.h>
#include <queue>
#include <vector>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <atomic>
#include <memory>

#define INITIAL_POOL_SIZE 8
// #define MAX_POOL_SIZE 64
#define POOL_GROW_THRESHOLD 100  // Threshold in percentage to grow the pool
#define POOL_SHRINK_THRESHOLD 50 // Threshold in percentage to shrink the pool
#define POOL_SHRINK_TIMEOUT 60   // Shrink timeout in seconds

void handle_task(global_config *global_conf);
void *handle_tcp_send(void *arg);
void *handle_tcp_recv(void *arg);
void *handle_udp_send(void *arg);
void *handle_udp_recv(void *arg);

void *manage_pool_size(void *arg);

// Forward declarations
struct Task;
class Thread;
class ThreadPool;

// Define the Task structure
struct Task {
    global_config config;
};

// Define the ThreadPool structure
class ThreadPool {
public:
    pthread_mutex_t lock;
    pthread_cond_t notify;
    std::vector<std::unique_ptr<Thread>> threads; // Store pointers to threads
    std::queue<Task> task_queue;
    int pool_size;
    int active_threads;
    bool stop;
    pthread_t timer_thread;

    ThreadPool(int initial_size);
    ~ThreadPool();
    static void* manage_pool_size(void *arg);
    void add_task(Task &&new_task);
};

class Thread {
public:
    pthread_t thread;
    std::atomic<bool> is_terminate;
    ThreadPool *pool;

    Thread(ThreadPool *pool);
    void signal_terminate();
    bool should_terminate() const;
    void run();
    void start();
    static void* start_routine(void* arg);
};