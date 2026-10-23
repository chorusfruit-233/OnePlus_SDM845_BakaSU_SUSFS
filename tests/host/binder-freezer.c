// SPDX-License-Identifier: GPL-2.0
/* Exercise the real 4.9 Binder driver inside a disposable ARM64 guest. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* This 4.9 UAPI still uses the kernel's spelling for this annotation. */
#define __packed __attribute__((packed))
#include <linux/android/binder.h>

_Static_assert(sizeof(struct binder_freeze_info) == 12, "freeze ABI");
_Static_assert(sizeof(struct binder_frozen_status_info) == 12, "status ABI");
_Static_assert(BINDER_FREEZE == 0x400c620e, "freeze ioctl ABI");
_Static_assert(BINDER_GET_FROZEN_INFO == 0xc00c620f, "status ioctl ABI");
_Static_assert(BR_FROZEN_REPLY == 0x7212, "frozen reply ABI");

enum { RECEIVE = 1, FINISH, DROP_THREAD, PING, STOP, FAULT_READ };
struct control { int op, device; };
struct response { uint32_t code, flags; };
struct endpoint { int fd; void *mapping; };
struct received {
    unsigned complete, reply, frozen, dead, failed, transaction;
    struct binder_transaction_data data;
};
static struct {
    pid_t pid;
    int command, response, devices;
    struct endpoint client[2];
} fixture = { .pid = -1, .command = -1, .response = -1,
              .client = {{.fd = -1}, {.fd = -1}} };
static const char *test_name;
static const char *devices[] = { "/dev/binder", "/dev/vndbinder" };
static char cgroup_path[160];
static volatile sig_atomic_t interrupted;

static void fail(const char *format, ...)
{
    va_list args;
    fprintf(stderr, "FAIL %s: ", test_name);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, " (errno=%d %s)\n", errno, strerror(errno));
    if (fixture.pid > 0)
        kill(fixture.pid, SIGKILL);
    exit(1);
}
#define CHECK(condition, ...) do { if (!(condition)) fail(__VA_ARGS__); } while (0)

static uint64_t milliseconds(void)
{
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now), "clock_gettime");
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void transfer(int fd, void *buffer, size_t size, bool writing)
{
    unsigned char *p = buffer;
    while (size) {
        ssize_t n = writing ? write(fd, p, size) : read(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        CHECK(n > 0, "control pipe transfer");
        p += n;
        size -= n;
    }
}

static void binder_write(int fd, uint32_t command, const void *data, size_t size)
{
    unsigned char bytes[256];
    struct binder_write_read bwr = {0};
    int ret;
    CHECK(size + sizeof(command) <= sizeof(bytes), "command size");
    memcpy(bytes, &command, sizeof(command));
    if (size)
        memcpy(bytes + sizeof(command), data, size);
    bwr.write_size = sizeof(command) + size;
    bwr.write_buffer = (uintptr_t)bytes;
    do { ret = ioctl(fd, BINDER_WRITE_READ, &bwr); } while (ret < 0 && errno == EINTR);
    CHECK(!ret && bwr.write_consumed == bwr.write_size, "Binder write command %#x", command);
}

static struct endpoint open_endpoint(int device, bool manager)
{
    struct endpoint ep;
    struct binder_version version;
    uint32_t threads = 0;
    ep.fd = open(devices[device], O_RDWR | O_NONBLOCK | O_CLOEXEC);
    CHECK(ep.fd >= 0, "open %s", devices[device]);
    ep.mapping = mmap(NULL, 1024 * 1024, PROT_READ, MAP_PRIVATE, ep.fd, 0);
    CHECK(ep.mapping != MAP_FAILED, "Binder mmap");
    CHECK(!ioctl(ep.fd, BINDER_VERSION, &version) && version.protocol_version == 8,
          "existing Binder protocol remains version 8");
    CHECK(!ioctl(ep.fd, BINDER_SET_MAX_THREADS, &threads), "set thread count");
    if (manager)
        CHECK(!ioctl(ep.fd, BINDER_SET_CONTEXT_MGR, NULL), "set context manager");
    binder_write(ep.fd, BC_ENTER_LOOPER, NULL, 0);
    return ep;
}

static void read_events(int fd, struct received *events)
{
    unsigned char bytes[2048];
    struct binder_write_read bwr = {
        .read_size = sizeof(bytes), .read_buffer = (uintptr_t)bytes,
    };
    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0 && (errno == EAGAIN || errno == EINTR))
        return;
    CHECK(!ret, "Binder read");
    size_t offset = 0;
    while (offset < bwr.read_consumed) {
        uint32_t command;
        CHECK(offset + sizeof(command) <= bwr.read_consumed, "short Binder command");
        memcpy(&command, bytes + offset, sizeof(command));
        offset += sizeof(command);
        size_t size = _IOC_SIZE(command);
        CHECK(offset + size <= bwr.read_consumed, "short Binder payload");
        switch (command) {
        case BR_TRANSACTION_COMPLETE: events->complete++; break;
        case BR_FROZEN_REPLY: events->frozen++; break;
        case BR_DEAD_REPLY: events->dead++; break;
        case BR_FAILED_REPLY: events->failed++; break;
        case BR_REPLY:
            events->reply++;
            memcpy(&events->data, bytes + offset, sizeof(events->data));
            break;
        case BR_TRANSACTION:
            events->transaction++;
            memcpy(&events->data, bytes + offset, sizeof(events->data));
            break;
        case BR_INCREFS: case BR_ACQUIRE:
            binder_write(fd, command == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE,
                         bytes + offset, size);
            break;
        case BR_NOOP: case BR_SPAWN_LOOPER: case BR_RELEASE: case BR_DECREFS:
            break;
        default: fail("unexpected Binder command %#x", command);
        }
        offset += size;
    }
}

static struct binder_transaction_data wait_result(int fd, uint32_t expected)
{
    uint64_t deadline = milliseconds() + 3000;
    struct received events = {0};
    while (milliseconds() < deadline) {
        read_events(fd, &events);
        CHECK(!events.transaction, "client unexpectedly received a request");
        CHECK(!events.frozen || expected == BR_FROZEN_REPLY, "unexpected frozen reply");
        CHECK(!events.dead || expected == BR_DEAD_REPLY, "unexpected dead reply");
        CHECK(!events.failed || expected == BR_FAILED_REPLY, "unexpected failed reply");
        if ((expected == BR_REPLY && events.reply) ||
            (expected == BR_TRANSACTION_COMPLETE && events.complete) ||
            (expected == BR_FROZEN_REPLY && events.frozen) ||
            (expected == BR_DEAD_REPLY && events.dead) ||
            (expected == BR_FAILED_REPLY && events.failed)) {
            if (events.reply) {
                CHECK(events.data.data_size == sizeof(uint32_t), "reply data size");
                uint32_t payload;
                memcpy(&payload, (void *)(uintptr_t)events.data.data.ptr.buffer, sizeof(payload));
                CHECK(payload == 0xb17de123, "reply payload survives round trip");
                binder_write(fd, BC_FREE_BUFFER, &events.data.data.ptr.buffer,
                             sizeof(binder_uintptr_t));
            }
            return events.data;
        }
        usleep(1000);
    }
    fail("timed out waiting for Binder command %#x", expected);
    return events.data;
}

static void send_transaction(int device, uint32_t code, bool oneway)
{
    uint32_t payload = code ^ 0xabcdef;
    struct binder_transaction_data transaction = {
        .code = code, .flags = oneway ? TF_ONE_WAY : 0,
        .data_size = sizeof(payload), .data.ptr.buffer = (uintptr_t)&payload,
    };
    binder_write(fixture.client[device].fd, BC_TRANSACTION, &transaction, sizeof(transaction));
}

static void server_loop(int input, int output, int count)
{
    struct endpoint ep[2];
    struct binder_transaction_data pending[2] = {0};
    struct response response = {0};
    for (int i = 0; i < count; i++)
        ep[i] = open_endpoint(i, true);
    transfer(output, &response, sizeof(response), true);
    for (;;) {
        struct control control;
        transfer(input, &control, sizeof(control), false);
        CHECK(control.device >= 0 && control.device < count, "server device index");
        int fd = ep[control.device].fd;
        response = (struct response){0};
        switch (control.op) {
        case RECEIVE: {
            struct received events = {0};
            uint64_t deadline = milliseconds() + 3000;
            while (!events.transaction && milliseconds() < deadline) {
                read_events(fd, &events);
                if (!events.transaction)
                    usleep(1000);
            }
            CHECK(events.transaction == 1, "server must receive exactly one request");
            pending[control.device] = events.data;
            uint32_t payload;
            CHECK(events.data.data_size == sizeof(payload), "request size");
            memcpy(&payload, (void *)(uintptr_t)events.data.data.ptr.buffer, sizeof(payload));
            CHECK(payload == (events.data.code ^ 0xabcdef), "request payload");
            response.code = events.data.code;
            response.flags = events.data.flags;
            break;
        }
        case FINISH: {
            struct binder_transaction_data *incoming = &pending[control.device];
            CHECK(incoming->data.ptr.buffer, "no transaction to finish");
            if (!(incoming->flags & TF_ONE_WAY)) {
                uint32_t payload = 0xb17de123;
                struct binder_transaction_data reply = {
                    .data_size = sizeof(payload), .data.ptr.buffer = (uintptr_t)&payload,
                };
                binder_write(fd, BC_REPLY, &reply, sizeof(reply));
            }
            binder_write(fd, BC_FREE_BUFFER, &incoming->data.ptr.buffer, sizeof(binder_uintptr_t));
            memset(incoming, 0, sizeof(*incoming));
            break;
        }
        case DROP_THREAD:
            CHECK(!ioctl(fd, BINDER_THREAD_EXIT, NULL), "release active server thread");
            binder_write(fd, BC_ENTER_LOOPER, NULL, 0);
            break;
        case FAULT_READ: {
            /* Skip the initial BR_NOOP, then fault delivering a queued request. */
            struct binder_write_read bwr = {
                .read_size = 256, .read_consumed = sizeof(uint32_t), .read_buffer = 1,
            };
            CHECK(ioctl(fd, BINDER_WRITE_READ, &bwr) == -1 && errno == EFAULT,
                  "fault during transaction delivery");
            break;
        }
        case PING: break;
        case STOP: _exit(0);
        default: fail("invalid server command");
        }
        transfer(output, &response, sizeof(response), true);
    }
}

static void start_server(int count)
{
    int command[2], response[2];
    CHECK(!pipe2(command, O_CLOEXEC) && !pipe2(response, O_CLOEXEC), "pipe2");
    fixture.pid = fork();
    CHECK(fixture.pid >= 0, "fork");
    if (!fixture.pid) {
        close(command[1]); close(response[0]);
        server_loop(command[0], response[1], count);
        _exit(1);
    }
    close(command[0]); close(response[1]);
    fixture.command = command[1]; fixture.response = response[0]; fixture.devices = count;
    struct response ready;
    transfer(fixture.response, &ready, sizeof(ready), false);
    for (int i = 0; i < count; i++)
        fixture.client[i] = open_endpoint(i, false);
}

static void command_async(int op, int device)
{
    struct control control = { op, device };
    transfer(fixture.command, &control, sizeof(control), true);
}

static struct response command_result(void)
{
    struct pollfd pfd = { .fd = fixture.response, .events = POLLIN };
    CHECK(poll(&pfd, 1, 3500) > 0, "server response timed out");
    struct response response;
    transfer(fixture.response, &response, sizeof(response), false);
    return response;
}

static struct response command_sync(int op, int device)
{
    command_async(op, device);
    return command_result();
}

static int freeze_pid(pid_t pid, bool enable, uint32_t timeout)
{
    struct binder_freeze_info info = { pid, enable, timeout };
    return ioctl(fixture.client[0].fd, BINDER_FREEZE, &info);
}

static struct binder_frozen_status_info status_pid(pid_t pid)
{
    struct binder_frozen_status_info info = { .pid = pid };
    CHECK(!ioctl(fixture.client[0].fd, BINDER_GET_FROZEN_INFO, &info), "get frozen status");
    return info;
}

static void round_trip(int device, uint32_t code)
{
    send_transaction(device, code, false);
    struct response response = command_sync(RECEIVE, device);
    CHECK(response.code == code && !(response.flags & TF_ONE_WAY), "received synchronous request");
    command_sync(FINISH, device);
    wait_result(fixture.client[device].fd, BR_REPLY);
}

static void stop_server(void)
{
    if (fixture.pid > 0) {
        CHECK(!freeze_pid(fixture.pid, false, 0), "final Binder thaw");
        command_async(STOP, 0);
        int status;
        CHECK(waitpid(fixture.pid, &status, 0) == fixture.pid && WIFEXITED(status) &&
              !WEXITSTATUS(status), "server exit");
    }
    close(fixture.command); close(fixture.response);
    for (int i = 0; i < fixture.devices; i++) {
        CHECK(!munmap(fixture.client[i].mapping, 1024 * 1024), "client munmap");
        close(fixture.client[i].fd);
        fixture.client[i].fd = -1;
    }
    fixture.pid = -1;
    /* Let deferred release remove the context manager before the next case. */
    usleep(20000);
}

static void test_interface(void)
{
    start_server(1);
    struct binder_freeze_info bad = { .pid = UINT32_MAX, .enable = 1 };
    struct binder_frozen_status_info status = { .pid = UINT32_MAX };
    int fd = fixture.client[0].fd;
    CHECK(ioctl(fd, BINDER_FREEZE, &bad) == -1 && errno == EINVAL, "unknown freeze PID rejected");
    CHECK(ioctl(fd, BINDER_GET_FROZEN_INFO, &status) == -1 && errno == EINVAL,
          "unknown status PID rejected");
    CHECK(ioctl(fd, BINDER_FREEZE, (void *)1) == -1 && errno == EFAULT, "bad freeze pointer");
    CHECK(ioctl(fd, BINDER_GET_FROZEN_INFO, (void *)1) == -1 && errno == EFAULT, "bad status pointer");
    CHECK(ioctl(fd, _IOW('b', 14, uint64_t), &bad) == -1 && errno == EINVAL,
          "incorrect ioctl size rejected");
    CHECK(!freeze_pid(fixture.pid, true, 100), "freeze idle target");
    command_sync(PING, 0); /* Binder freezing alone must not stop scheduling. */
    status = status_pid(fixture.pid);
    CHECK(!status.sync_recv && !status.async_recv, "initial receive flags clear");
    CHECK(!freeze_pid(fixture.pid, false, 0), "thaw idle target");
    stop_server();
}

static void test_sync_rejected(void)
{
    start_server(1);
    CHECK(!freeze_pid(fixture.pid, true, 0), "freeze");
    send_transaction(0, 101, false);
    wait_result(fixture.client[0].fd, BR_FROZEN_REPLY);
    struct binder_frozen_status_info status = status_pid(fixture.pid);
    CHECK(status.sync_recv == 1 && !status.async_recv, "sync receive flag without queued transaction");
    CHECK(!freeze_pid(fixture.pid, false, 0), "thaw");
    status = status_pid(fixture.pid);
    CHECK(!status.sync_recv && !status.async_recv, "thaw clears receive flags");
    round_trip(0, 102);
    stop_server();
}

static void write_file(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    CHECK(fd >= 0, "open %s", path);
    CHECK(write(fd, value, strlen(value)) == (ssize_t)strlen(value), "write %s", path);
    close(fd);
}

static void cgroup_freeze(bool enable)
{
    char path[200];
    snprintf(path, sizeof(path), "%s/cgroup.freeze", cgroup_path);
    write_file(path, enable ? "1" : "0");
    snprintf(path, sizeof(path), "%s/cgroup.events", cgroup_path);
    uint64_t deadline = milliseconds() + 3000;
    while (milliseconds() < deadline) {
        char contents[256] = {0};
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0, "open cgroup.events");
        CHECK(read(fd, contents, sizeof(contents) - 1) > 0, "read cgroup.events");
        close(fd);
        if (strstr(contents, enable ? "frozen 1\n" : "frozen 0\n"))
            return;
        usleep(1000);
    }
    fail("cgroup freeze state timed out");
}

static void test_async_cgroup(void)
{
    start_server(1);
    char path[200], pid[24];
    snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/binder-test-%d", getpid());
    CHECK(!mkdir(cgroup_path, 0755), "create test cgroup");
    snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path);
    snprintf(pid, sizeof(pid), "%d", fixture.pid);
    write_file(path, pid);
    CHECK(!freeze_pid(fixture.pid, true, 0), "freeze Binder before cgroup");
    cgroup_freeze(true);
    for (uint32_t i = 1; i <= 3; i++) {
        send_transaction(0, i, true);
        wait_result(fixture.client[0].fd, BR_TRANSACTION_COMPLETE);
    }
    struct binder_frozen_status_info status = status_pid(fixture.pid);
    CHECK(status.async_recv == 1 && status.sync_recv == 2, "async flag and pending bit");
    command_async(RECEIVE, 0);
    struct pollfd pfd = { .fd = fixture.response, .events = POLLIN };
    CHECK(!poll(&pfd, 1, 50), "frozen server cannot process a request");
    CHECK(!freeze_pid(fixture.pid, false, 0), "Binder thaw");
    CHECK(!poll(&pfd, 1, 50), "Binder thaw alone cannot resume cgroup-frozen server");
    cgroup_freeze(false);
    for (uint32_t i = 1; i <= 3; i++) {
        struct response response = i == 1 ? command_result() : command_sync(RECEIVE, 0);
        CHECK(response.code == i && (response.flags & TF_ONE_WAY), "async delivery order after thaw");
        command_sync(FINISH, 0);
    }
    status = status_pid(fixture.pid);
    CHECK(!status.sync_recv && !status.async_recv, "all queued async work drained");
    snprintf(pid, sizeof(pid), "%d", fixture.pid);
    write_file("/sys/fs/cgroup/cgroup.procs", pid);
    CHECK(!rmdir(cgroup_path), "remove test cgroup");
    cgroup_path[0] = 0;
    round_trip(0, 104);
    stop_server();
}

static void drain_request(void)
{
    command_sync(RECEIVE, 0);
    command_sync(FINISH, 0);
    wait_result(fixture.client[0].fd, BR_REPLY);
}

static void test_pending_rollback(void)
{
    start_server(1);
    send_transaction(0, 201, false);
    CHECK(status_pid(fixture.pid).sync_recv == 2, "queued request is reported pending");
    CHECK(freeze_pid(fixture.pid, true, 0) == -1 && errno == EAGAIN,
          "busy target cannot freeze without waiting");
    drain_request();
    round_trip(0, 202); /* Failure must roll back is_frozen. */
    CHECK(!freeze_pid(fixture.pid, true, 0), "transaction accounting drains to zero");
    stop_server();
}

static void test_timeout_rollback(void)
{
    start_server(1);
    send_transaction(0, 301, false);
    uint64_t start = milliseconds();
    CHECK(freeze_pid(fixture.pid, true, 100) == -1 && errno == EAGAIN, "freeze timeout");
    uint64_t elapsed = milliseconds() - start;
    CHECK(elapsed >= 60 && elapsed < 1500, "timeout is bounded: %llu ms", (unsigned long long)elapsed);
    drain_request();
    round_trip(0, 302);
    stop_server();
}

static void *delayed_drain(void *unused)
{
    (void)unused;
    usleep(70000);
    command_sync(RECEIVE, 0);
    command_sync(FINISH, 0);
    return NULL;
}

static void test_wait_drain(void)
{
    start_server(1);
    send_transaction(0, 401, false);
    pthread_t worker;
    CHECK(!pthread_create(&worker, NULL, delayed_drain, NULL), "start delayed receiver");
    uint64_t start = milliseconds();
    CHECK(!freeze_pid(fixture.pid, true, 1500), "wait for accepted transaction to complete");
    CHECK(milliseconds() - start < 1200, "drained transaction wakes freezer before timeout");
    CHECK(!pthread_join(worker, NULL), "join delayed receiver");
    wait_result(fixture.client[0].fd, BR_REPLY);
    send_transaction(0, 402, false);
    wait_result(fixture.client[0].fd, BR_FROZEN_REPLY);
    stop_server();
}

static void signal_handler(int signal)
{
    (void)signal;
    interrupted = 1;
}

static void *delayed_signal(void *target)
{
    usleep(70000);
    CHECK(!pthread_kill(*(pthread_t *)target, SIGUSR1), "interrupt freeze wait");
    return NULL;
}

static void test_interrupted_rollback(void)
{
    start_server(1);
    struct sigaction action = { .sa_handler = signal_handler };
    sigemptyset(&action.sa_mask);
    CHECK(!sigaction(SIGUSR1, &action, NULL), "install signal handler");
    interrupted = 0;
    send_transaction(0, 501, false);
    pthread_t worker, current = pthread_self();
    CHECK(!pthread_create(&worker, NULL, delayed_signal, &current), "start signal worker");
    CHECK(freeze_pid(fixture.pid, true, 1500) == -1 && errno == EINTR, "signal interrupts wait");
    CHECK(!pthread_join(worker, NULL) && interrupted, "signal delivered");
    drain_request();
    round_trip(0, 502);
    stop_server();
}

static void test_outgoing_pending(void)
{
    start_server(1);
    send_transaction(0, 601, false);
    CHECK(status_pid(getpid()).sync_recv == 2, "outbound stack reported pending");
    CHECK(freeze_pid(getpid(), true, 0) == -1 && errno == EAGAIN,
          "caller waiting for reply cannot freeze");
    drain_request();
    CHECK(!freeze_pid(getpid(), true, 0), "caller freezes after reply read");
    CHECK(!freeze_pid(getpid(), false, 0), "caller thaw");
    stop_server();
}

static void test_thread_exit(void)
{
    start_server(1);
    send_transaction(0, 701, false);
    command_sync(RECEIVE, 0);
    CHECK(status_pid(fixture.pid).sync_recv == 2, "active server stack reported pending");
    command_sync(DROP_THREAD, 0);
    wait_result(fixture.client[0].fd, BR_DEAD_REPLY);
    CHECK(!freeze_pid(fixture.pid, true, 0), "thread exit releases outstanding count");
    CHECK(!freeze_pid(fixture.pid, false, 0), "thaw after thread exit");
    round_trip(0, 702);
    stop_server();
}

static void test_process_exit(void)
{
    start_server(1);
    send_transaction(0, 801, false);
    command_sync(RECEIVE, 0);
    CHECK(!kill(fixture.pid, SIGKILL), "kill server with active request");
    int status;
    CHECK(waitpid(fixture.pid, &status, 0) == fixture.pid && WIFSIGNALED(status), "wait killed server");
    wait_result(fixture.client[0].fd, BR_DEAD_REPLY);
    fixture.pid = -1;
    stop_server();
}

static void test_delivery_fault(void)
{
    start_server(1);
    send_transaction(0, 850, false);
    command_sync(FAULT_READ, 0);
    wait_result(fixture.client[0].fd, BR_FAILED_REPLY);
    CHECK(!status_pid(fixture.pid).sync_recv, "faulted delivery releases outstanding count");
    CHECK(!freeze_pid(fixture.pid, true, 0), "freeze after failed delivery");
    CHECK(!freeze_pid(fixture.pid, false, 0), "thaw after failed delivery");
    round_trip(0, 851);
    stop_server();
}

static void *delayed_exit(void *unused)
{
    (void)unused;
    usleep(70000);
    CHECK(!kill(fixture.pid, SIGKILL), "kill target while freezer holds reference");
    return NULL;
}

static void test_exit_during_wait(void)
{
    start_server(1);
    send_transaction(0, 860, false);
    pthread_t worker;
    CHECK(!pthread_create(&worker, NULL, delayed_exit, NULL), "start exit worker");
    uint64_t start = milliseconds();
    CHECK(!freeze_pid(fixture.pid, true, 250), "freeze wait safely handles target exit");
    CHECK(milliseconds() - start < 1500, "dead target wait is bounded");
    CHECK(!pthread_join(worker, NULL), "join exit worker");
    int status;
    CHECK(waitpid(fixture.pid, &status, 0) == fixture.pid && WIFSIGNALED(status), "wait dead target");
    wait_result(fixture.client[0].fd, BR_DEAD_REPLY);
    fixture.pid = -1;
    stop_server();
}

static void test_multiple_contexts(void)
{
    start_server(2);
    CHECK(!freeze_pid(fixture.pid, true, 0), "freeze all Binder opens of PID");
    for (int i = 0; i < 2; i++) {
        send_transaction(i, 901 + i, false);
        wait_result(fixture.client[i].fd, BR_FROZEN_REPLY);
    }
    send_transaction(1, 903, true);
    wait_result(fixture.client[1].fd, BR_TRANSACTION_COMPLETE);
    struct binder_frozen_status_info status = status_pid(fixture.pid);
    CHECK(status.sync_recv == 3 && status.async_recv == 1, "status aggregates all PID contexts");
    CHECK(!freeze_pid(fixture.pid, false, 0), "thaw all contexts");
    CHECK(command_sync(RECEIVE, 1).code == 903, "queued vendor request delivered");
    command_sync(FINISH, 1);
    round_trip(0, 904);
    round_trip(1, 905);
    stop_server();
}

static void test_repeated_cycles(void)
{
    start_server(1);
    for (unsigned i = 0; i < 50; i++) {
        CHECK(!freeze_pid(fixture.pid, true, 0), "cycle freeze");
        send_transaction(0, 1000 + i, false);
        wait_result(fixture.client[0].fd, BR_FROZEN_REPLY);
        CHECK(!freeze_pid(fixture.pid, false, 0), "cycle thaw");
        round_trip(0, 2000 + i);
    }
    stop_server();
}

int main(int argc, char **argv)
{
    char command_line[4096] = {0};
    int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && read(fd, command_line, sizeof(command_line) - 1) > 0,
          "read guest boot marker");
    close(fd);
    CHECK(strstr(command_line, "binder_freezer_backport_qemu=1"),
          "run only in the dedicated disposable QEMU guest");
    if (argc == 2 && !strcmp(argv[1], "--shutdown")) {
        sync();
        CHECK(!reboot(RB_AUTOBOOT), "reboot test guest");
        return 1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("BINDER_FREEZER_ABI=%u\n", (unsigned)(sizeof(void *) * 8));
    signal(SIGPIPE, SIG_IGN);
    static const struct { const char *name; void (*run)(void); } tests[] = {
        {"interface", test_interface}, {"sync_rejected", test_sync_rejected},
        {"async_cgroup", test_async_cgroup}, {"pending_rollback", test_pending_rollback},
        {"timeout_rollback", test_timeout_rollback}, {"wait_drain", test_wait_drain},
        {"interrupted_rollback", test_interrupted_rollback},
        {"outgoing_pending", test_outgoing_pending}, {"thread_exit", test_thread_exit},
        {"process_exit", test_process_exit}, {"delivery_fault", test_delivery_fault},
        {"exit_during_wait", test_exit_during_wait}, {"multiple_contexts", test_multiple_contexts},
        {"repeated_cycles", test_repeated_cycles},
    };
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        test_name = tests[i].name;
        tests[i].run();
        printf("PASS binder_%s\n", test_name);
    }
    puts("BINDER_FREEZER_TESTS_PASS");
    return 0;
}
