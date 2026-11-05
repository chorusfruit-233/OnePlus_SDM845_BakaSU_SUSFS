// SPDX-License-Identifier: GPL-2.0-only
// Fault injection around the actual hm_process_payload() function.
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
#define GFP_KERNEL 0
#define PAGE_SIZE 4096
#define FOLL_WRITE 1
#define offset_in_page(x) ((x) & (PAGE_SIZE - 1))
#define unlikely(x) (x)
#define hm_err(...) ((void)0)
#define hm_warn(...) ((void)0)
#define HYBRIDMOUNT_MAGIC_SIG UINT64_C(0x4859425249444D4F)
#define HYBRIDMOUNT_VERSION "hm1"
#define READ_ONCE(x) (x)
#define rcu_dereference(x) (x)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define synchronize_rcu() ((void)0)
#define synchronize_srcu(x) ((void)0)
#define HM_CLEAR_UIDS 1
#define HM_CLEAR_RULES 2
#define HM_CLEAR_EXIT 4
#define LIST_HEAD(x) int x=0
#define list_empty(x) (1)
#define list_for_each_entry_safe(a,b,list,node) for ((a)=NULL; (a); (a)=NULL)
#define list_for_each_entry(a,list,node) for ((a)=NULL; (a); (a)=NULL)
#define down_read(x) ((void)0)
#define up_read(x) ((void)0)
#define down_write(x) ((void)0)
#define up_write(x) ((void)0)
struct page { int unused; };
struct hm_payload {
    uint64_t magic; uint32_t cmd, target_uid; int32_t status;
    uint32_t arg1, data_size; char buffer[4068];
} __attribute__((packed));
struct hm_rule_hdr { uint32_t flags, uid; uint16_t v_len, r_len; } __attribute__((packed));
struct hm_del_hdr { uint32_t uid; uint16_t v_len; } __attribute__((packed));
struct hybridmount_rule { uint16_t v_len, r_len; uint32_t flags, target_uid; };
struct hm_uid_array { int count; u32 uids[2]; };
static struct hm_uid_array *hybridmount_uids;
enum { HM_CMD_GET_VERSION=1, HM_CMD_ADD_RULE, HM_CMD_DEL_RULE, HM_CMD_ADD_UID,
    HM_CMD_DEL_UID, HM_CMD_CLEAR_ALL, HM_CMD_CLEAR_RULES, HM_CMD_CLEAR_UIDS,
    HM_CMD_GET_LIST, HM_CMD_GET_UIDS };
static struct hm_payload *shared;
static struct page pinned;
static int pins, maps, allocations, dirty, adds;
static bool fail_pin, fail_alloc;
static int get_user_pages_fast(unsigned long addr, int n, int flags, struct page **p) {
    if (fail_pin) return 0;
    assert(addr == (unsigned long)shared); pins++; *p=&pinned; return 1;
}
static void *kmap(struct page *p) { assert(pins==1 && p==&pinned); maps++; return shared; }
static void kunmap(struct page *p) { assert(maps==1); maps--; }
static void put_page(struct page *p) { assert(pins==1); pins--; }
static void set_page_dirty_lock(struct page *p) { dirty++; }
static void *kmemdup(void *p, size_t size, int flags) {
    if (fail_alloc) return NULL;
    void *q=malloc(size); assert(q); memcpy(q,p,size); allocations++; return q;
}
static void kfree(void *p) { assert(allocations==1); allocations--; free(p); }
static void hm_free_rule(struct hybridmount_rule *p) { }
static const char *hm_get_vpath(struct hybridmount_rule *p) { return ""; }
static const char *hm_get_rpath(struct hybridmount_rule *p) { return ""; }
static int hm_uid_add(u32 uid) { return 0; }
static int hm_uid_del(u32 uid) { return 0; }
static void __hybridmount_clear_all(int flags) { }
static int __hybridmount_del_rule(char *v, int len, int uid, int *list) { return 0; }
static int __hybridmount_add_rule(char *v, char *r, int vl, int rl, int flags, int uid, int *list) {
    assert(vl==2 && rl==2 && !memcmp(v,"/v",2) && !memcmp(r,"/r",2));
    adds++;
    if (adds==1) {
        // Model another userspace thread rewriting the NEXT record during path lookup.
        struct hm_rule_hdr *next=(void *)(shared->buffer+sizeof(*next)+4);
        next->v_len=UINT16_MAX;
        shared->data_size=UINT32_MAX;
        shared->arg1=UINT32_MAX;
    }
    return 0;
}
#include "production.h"
static void reset(void) {
    memset(shared,0,sizeof(*shared));
    shared->magic=HYBRIDMOUNT_MAGIC_SIG; shared->cmd=HM_CMD_GET_VERSION;
    fail_alloc=fail_pin=false; dirty=adds=0;
    assert(!pins && !maps && !allocations);
}
int main(void) {
    assert(!posix_memalign((void **)&shared,PAGE_SIZE,PAGE_SIZE));
    reset(); shared->cmd=HM_CMD_ADD_RULE;
    struct hm_rule_hdr h={.v_len=2,.r_len=2};
    for(int i=0;i<2;i++) {
        char *p=shared->buffer+i*(sizeof(h)+4);
        memcpy(p,&h,sizeof(h)); memcpy(p+sizeof(h),"/v/r",4);
    }
    shared->data_size=2*(sizeof(h)+4);
    assert(hm_process_payload((unsigned long)shared)==0);
    assert(adds==2 && shared->status==0 && shared->arg1==2*(sizeof(h)+4));
    assert(!pins && !maps && !allocations && dirty==1);
    reset(); fail_pin=true;
    assert(hm_process_payload((unsigned long)shared)==-EFAULT);
    reset(); fail_alloc=true;
    assert(hm_process_payload((unsigned long)shared)==-ENOMEM);
    assert(!pins && !maps && !allocations && !dirty);
    reset(); shared->magic=0;
    assert(hm_process_payload((unsigned long)shared)==-EFAULT);
    assert(!pins && !maps && !allocations && !dirty);
    reset(); assert(hm_process_payload((unsigned long)shared)==0);
    assert(!memcmp(shared->buffer,"hm1",3) && shared->data_size==3 && dirty==1);
    free(shared);
    puts("PASS Hybrid Mount concurrent user-buffer mutation and pin/allocation cleanup");
}
