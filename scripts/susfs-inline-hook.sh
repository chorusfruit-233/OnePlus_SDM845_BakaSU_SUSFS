#!/usr/bin/env bash
# SUSFS v2.3.0 inline-hook patcher for non-GKI kernels.
#
# Based on Patches/susfs_inline_hook_patches.sh from
# https://github.com/JackA1ltman/NonGKI_Kernel_Build_2nd
# (patch author: simonpunk @ Gitlab, backslashxx @ Github)
#
# Adapted for BakaSU on Linux 4.9:
#  - ksu_handle_sys_read() uses BakaSU's three-argument signature
#    (unsigned int fd, char __user **buf_ptr, size_t *count_ptr);
#  - the security/security.c section is dropped: BakaSU registers its
#    own LSM hooks and does not export ksu_bprm_check()/cred-based
#    ksu_handle_setuid();
#  - any section that fails to apply aborts the build instead of
#    silently continuing.
set -euo pipefail

KERNEL_ROOT="${1:-.}"
cd "$KERNEL_ROOT"

FAILED=0

fail() {
    echo "[-] $1"
    FAILED=1
}

patch_files=(
    fs/exec.c
    fs/open.c
    fs/read_write.c
    fs/stat.c
    fs/namei.c
    drivers/input/input.c
    security/selinux/hooks.c
    security/selinux/ss/services.c
    kernel/reboot.c
    kernel/sys.c
    include/linux/seccomp.h
)

KERNEL_VERSION=$(head -n 3 Makefile | grep -E 'VERSION|PATCHLEVEL' | awk '{print $3}' | paste -sd '.')
FIRST_VERSION=$(echo "$KERNEL_VERSION" | awk -F '.' '{print $1}')
SECOND_VERSION=$(echo "$KERNEL_VERSION" | awk -F '.' '{print $2}')

echo "SUSFS inline hook patcher, kernel $KERNEL_VERSION"

for i in "${patch_files[@]}"; do

    if grep -q "ksu_handle" "$i"; then
        echo "[-] Warning: $i contains KernelSU"
        echo "[+] Code in here:"
        grep -n "ksu_handle" "$i"
        echo "[-] End of file."
        echo "======================================"
        continue
    fi

    case $i in
    ## exec.c
    fs/exec.c)
        echo "======================================"

        if grep -q "vmalloc.h" "fs/exec.c"; then
            sed -i '/#include <linux\/vmalloc.h>/a\#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif' fs/exec.c
        else
            sed -i '/#include <linux\/user_namespace.h>/a\#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif' fs/exec.c
        fi

        if grep -q "__do_execve_file" "fs/exec.c"; then
            sed -i '/static int __do_execve_file(int fd, struct filename \*filename,/i #ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n\t\t\tvoid *envp, int *flags);\nextern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv,\n\t\t\t\tvoid *envp, int *flags);\nextern int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr,\n\t\t\tvoid *argv, void *envp, int *flags, int *retval);\n#endif' fs/exec.c
        else
            sed -i '/^static int do_execveat_common(int fd, struct filename \*filename,/i\#ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n\t\t\tvoid *envp, int *flags);\nextern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,\n\t\t\t\t void *argv, void *envp, int *flags);\nextern int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr,\n\t\t\tvoid *argv, void *envp, int *flags, int *retval);\n#endif\n' fs/exec.c
        fi
        sed -i '/if (IS_ERR(filename))/i\#ifdef CONFIG_KSU_SUSFS\n\tbool is_su_session = false;\n#endif' fs/exec.c
        sed -i '/return PTR_ERR(filename);/a\#ifdef CONFIG_KSU_SUSFS\n\tif (likely(susfs_is_current_proc_no_su()))\n\t\tgoto orig_flow;\n\tif (static_branch_likely(\&ksu_su_compat_enabled)) {\n\t\tif (static_branch_unlikely(\&susfs_is_sdcard_android_data_not_decrypted))\n\t\t\tis_su_session = !ksu_handle_execveat(\&fd, \&filename, \&argv, \&envp, \&flags);\n\t\telse\n\t\t\tis_su_session = !ksu_handle_execveat_sucompat(\&fd, \&filename, \&argv, \&envp, \&flags);\n\t}\norig_flow:\n#endif' fs/exec.c

        # Install the su fd only after exec succeeds, before filename is freed.
        sed -i '/\/\* execve succeeded \*\//a\#ifdef CONFIG_KSU_SUSFS\n\tif (unlikely(is_su_session))\n\t\t(void)ksu_handle_post_execveat_sucompat(\&fd, \&filename, \&argv, \&envp, \&flags, \&retval);\n#endif' fs/exec.c

        if grep -q '^[[:space:]]*(void)ksu_handle_post_execveat_sucompat' fs/exec.c &&
           grep -q "ksu_handle_execveat_sucompat" "fs/exec.c"; then
            echo "[+] fs/exec.c Patched!"
            echo "[+] Count: $(grep -c "ksu_handle_execveat_sucompat" "fs/exec.c")"
        else
            fail "fs/exec.c patch failed for unknown reasons."
        fi

        echo "======================================"
        ;;
    ## open.c
    fs/open.c)
        sed -i '/#include <linux\/compat.h>/a #ifdef CONFIG_KSU_SUSFS\n#include <linux\/susfs_def.h>\n#endif' fs/open.c

        if grep -q "do_faccessat" "fs/open.c" >/dev/null 2>&1; then
            if grep -q "static int filename_lookup" "fs/namei.c" ; then
                sed -i '/long do_faccessat(int dfd, const char __user \*filename, int mode)/i #ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,\n\t\t\tint *flags);\nextern int filename_lookup(int dfd, struct filename *name, unsigned flags,\n\t\t\t\tstruct path *path, struct path *root);\n#endif' fs/open.c
            else
                sed -i '/long do_faccessat(int dfd, const char __user \*filename, int mode)/i #ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,\n\t\t\tint *flags);\n#endif' fs/open.c
            fi
        else
            if grep -q "static int filename_lookup" "fs/namei.c" ; then
                sed -i '/SYSCALL_DEFINE3(faccessat/i #ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,\n             int *flags);\nextern int filename_lookup(int dfd, struct filename *name, unsigned flags,\n\t\t\t\tstruct path *path, struct path *root);\n#endif' fs/open.c
            else
                sed -i '/SYSCALL_DEFINE3(faccessat/i #ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,\n             int *flags);\n#endif' fs/open.c
            fi
        fi
        sed -i '/if (mode & ~S_IRWXO)/i\#ifdef CONFIG_KSU_SUSFS\n\tstruct filename *fname = NULL;\n#endif\n' fs/open.c
        sed -i '/res = user_path_at(dfd, filename, lookup_flags, \&path);/i\#ifdef CONFIG_KSU_SUSFS\n\tfname = getname_flags(filename, lookup_flags, NULL);\n\n\tif (likely(susfs_is_current_proc_no_su()))\n\t\tgoto orig_flow;\n\n\tif (static_branch_likely(\&ksu_su_compat_enabled)) {\n\t\tif (unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))\n\t\t\tksu_handle_faccessat(\&dfd, \&fname, \&mode, NULL);\n\t}\n\norig_flow:\n\tres = filename_lookup(dfd, fname, lookup_flags, \&path, NULL);\n\t\/\/ no putname(fname) here as filename_lookup() has it done for us already;\n#else' fs/open.c
        sed -i '/res = user_path_at(dfd, filename, lookup_flags, \&path);/a\#endif' fs/open.c

        if grep -q "ksu_handle_faccessat" "fs/open.c"; then
            echo "[+] fs/open.c Patched!"
            echo "[+] Count: $(grep -c "ksu_handle_faccessat" "fs/open.c")"
        else
            fail "fs/open.c patch failed for unknown reasons."
        fi

        echo "======================================"
        ;;
    ## read_write.c
    fs/read_write.c)
        sed -i '/SYSCALL_DEFINE3(read,/i #ifdef CONFIG_KSU\nextern struct static_key_true ksu_is_init_rc_hook_enabled;\nextern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,\n\t\t\tchar __user **buf_ptr, size_t *count_ptr);\n#endif' fs/read_write.c
        if grep -q "ksys_read" "fs/read_write.c" >/dev/null 2>&1; then
            sed -i '/return ksys_read(fd, buf, count);/i #ifdef CONFIG_KSU\n\tif (static_branch_unlikely(\&ksu_is_init_rc_hook_enabled))\n\t\tksu_handle_sys_read(fd, \&buf, \&count);\n#endif' fs/read_write.c
        else
            sed -i '0,/if (f\.file) {/{s/if (f\.file) {/\n#ifdef CONFIG_KSU\n\tif (static_branch_unlikely(\&ksu_is_init_rc_hook_enabled))\n\t\tksu_handle_sys_read(fd, \&buf, \&count);\n#endif\n\tif (f.file) {/}' fs/read_write.c
        fi

        if grep -q "ksu_handle_sys_read" "fs/read_write.c"; then
            echo "[+] fs/read_write.c Patched!"
            echo "[+] Count: $(grep -c "ksu_handle_sys_read" "fs/read_write.c")"
        else
            fail "fs/read_write.c patch failed for unknown reasons."
        fi

        echo "======================================"
        ;;
    ## stat.c
    fs/stat.c)
        if grep -q "unistd" "fs/stat.c" && ! grep -q "susfs_def.h" "fs/stat.c"; then
            sed -i '/#include <asm\/unistd.h>/a\#ifdef CONFIG_KSU_SUSFS\n#include <linux\/susfs_def.h>\n#endif' fs/stat.c
        elif ! grep -q "susfs_def.h" "fs/stat.c"; then
            if grep -q "vmalloc.h" "fs/stat.c"; then
                sed -i '/#include <linux\/vmalloc.h>/a\#ifdef CONFIG_KSU_SUSFS\n#include <linux\/susfs_def.h>\n#endif' fs/stat.c
            else
                sed -i '/#include <asm\/uaccess.h>/i #ifdef CONFIG_KSU_SUSFS\n#include <linux\/susfs_def.h>\n#endif' fs/stat.c
            fi
        fi

        if ! grep -q "internal.h" "fs/stat.c"; then
            sed -i '/#include <asm\/unistd.h>/a\#include "internal.h"' fs/stat.c
        fi

        if grep -q "vfs_statx_fd" "fs/stat.c"; then
            sed -i '/int vfs_statx_fd(unsigned int fd, struct kstat \*stat,/i\#ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_is_init_rc_hook_enabled;\nextern void ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr);\n#endif \/\/ #ifdef CONFIG_KSU_SUSFS\n' fs/stat.c

        elif grep -q "vfs_fstat" "fs/stat.c"; then
            sed -i '/int vfs_fstat(unsigned int fd, struct kstat \*stat)/i\#ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_is_init_rc_hook_enabled;\nextern void ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr);\n#endif \/\/ #ifdef CONFIG_KSU_SUSFS\n' fs/stat.c

        else
            fail "Kernel have no vfs_statx_fd and vfs_fstat."
        fi

        if grep -q "vfs_statx" "fs/stat.c"; then
            if grep -q "static int filename_lookup" "fs/namei.c" ; then
                sed -i '/^int vfs_statx(int dfd, const char __user \*filename, int flags,/i\#ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);\nextern int filename_lookup(int dfd, struct filename *name, unsigned flags,\n\t\t\t\tstruct path *path, struct path *root);\n#endif\n' fs/stat.c
            else
                sed -i '/^int vfs_statx(int dfd, const char __user \*filename, int flags,/i\#ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);\n#endif\n' fs/stat.c
            fi

        elif grep -q "vfs_fstatat" "fs/stat.c"; then
            sed -i '/^int vfs_fstatat(int dfd, const char __user \*filename, struct kstat \*stat,/i\#ifdef CONFIG_KSU_SUSFS\nextern struct static_key_true ksu_su_compat_enabled;\nextern bool __ksu_is_allow_uid_for_current(uid_t uid);\nextern int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);\n#endif\n' fs/stat.c

        else
            fail "Kernel have no vfs_statx and vfs_fstatat."
        fi

        sed -i '/if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |/i\#ifdef CONFIG_KSU_SUSFS\n\tstruct filename *fname = NULL;\n#endif\n' fs/stat.c
        sed -i '/error = user_path_at(dfd, filename, lookup_flags, \&path);/i\#ifdef CONFIG_KSU_SUSFS\n\tfname = getname_flags(filename, lookup_flags, NULL);\n\n\tif (likely(susfs_is_current_proc_no_su()))\n\t\tgoto orig_flow;\n\n\tif (static_branch_likely(\&ksu_su_compat_enabled)) {\n\t\tif (unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))\n\t\t\tksu_handle_stat(\&dfd, \&fname, \&flags);\n\t}\n\norig_flow:\n\terror = filename_lookup(dfd, fname, lookup_flags, \&path, NULL);\n\t\/\/ no putname(fname) here as filename_lookup() has it done for us already;\n#else' fs/stat.c
        sed -i '/error = user_path_at(dfd, filename, lookup_flags, \&path);/a\#endif' fs/stat.c
        sed -i '/fdput(f);/i\#ifdef CONFIG_KSU_SUSFS\n\t\tif (static_branch_unlikely(\&ksu_is_init_rc_hook_enabled))\n\t\t\tksu_handle_vfs_fstat(fd, \&stat->size);\n#endif \/\/ #ifdef CONFIG_KSU_SUSFS\n' fs/stat.c

        if grep -q "ksu_handle_stat" "fs/stat.c"; then
            echo "[+] fs/stat.c Patched!"
            echo "[+] Count: $(grep -c "ksu_handle_stat" "fs/stat.c")"
        else
            fail "fs/stat.c patch failed for unknown reasons."
        fi

        echo "======================================"
        ;;
    ## namei.c
    fs/namei.c)
        if grep "static int filename_lookup" "fs/namei.c" ; then
            sed -i 's/static int filename_lookup(int dfd, struct filename \*name, unsigned flags,/int filename_lookup(int dfd, struct filename *name, unsigned flags,/' fs/namei.c
            echo "[+] fs/namei.c removed static status."
        fi

        if grep "throne_tracker" "fs/namei.c" >/dev/null 2>&1; then
            echo "[-] Warning: fs/namei.c contains KernelSU"
            echo "[+] Code in here:"
            grep -n "throne_tracker" "fs/namei.c"
            echo "[-] End of file."
        elif [ "$FIRST_VERSION" -lt 4 ] && [ "$SECOND_VERSION" -lt 19 ]; then
            sed -i '/if (unlikely(err)) {/a \#ifdef CONFIG_KSU\n\t\tif (unlikely(strstr(current->comm, "throne_tracker"))) {\n\t\t\terr = -ENOENT;\n\t\t\tgoto out_err;\n\t\t}\n#endif' fs/namei.c

            if grep -q "throne_tracker" "fs/namei.c"; then
                echo "[+] fs/namei.c Patched!"
                echo "[+] Count: $(grep -c "throne_tracker" "fs/namei.c")"
            else
                fail "fs/namei.c patch failed for unknown reasons."
            fi
        else
            echo "[-] Kernel needn't throne_tracker, Skipped."
        fi

        echo "======================================"
        ;;

    # drivers/ changes
    ## input/input.c
    drivers/input/input.c)
        sed -i '/^static void input_handle_event(struct input_dev \*dev,/i\#ifdef CONFIG_KSU\nextern struct static_key_true ksu_is_input_hook_enabled;\nextern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);\n#endif\n' drivers/input/input.c
        sed -i '/input_get_disposition(dev, type, code, \&value);/a\#ifdef CONFIG_KSU_SUSFS\n\tif (static_branch_unlikely(\&ksu_is_input_hook_enabled))\n\t\tksu_handle_input_handle_event(\&type, \&code, \&value);\n#endif\n' drivers/input/input.c

        if grep -q "ksu_handle_input_handle_event" "drivers/input/input.c"; then
            echo "[+] drivers/input/input.c Patched!"
            echo "[+] Count: $(grep -c "ksu_handle_input_handle_event" "drivers/input/input.c")"
        else
            fail "drivers/input/input.c patch failed for unknown reasons."
        fi

        echo "======================================"
        ;;

    # security/ changes
    ## selinux/hooks.c
    security/selinux/hooks.c)
        if grep "security_secid_to_secctx" "security/selinux/hooks.c"; then
            echo "[-] Detected security_secid_to_secctx existed, security/selinux/hooks.c Patched!"
        else
            sed -i '/int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);/i\#ifdef CONFIG_KSU\n    static u32 ksu_sid;\n    char *secdata;\n#endif' security/selinux/hooks.c
            sed -i '/if (!nnp && !nosuid)/i\#ifdef CONFIG_KSU\n    int error;\n    u32 seclen;\n#endif' security/selinux/hooks.c
            sed -i '/return 0; \/\* No change in credentials \*\//a\\n#ifdef CONFIG_KSU\n    if (!ksu_sid)\n        security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);\n\n    error = security_secid_to_secctx(old_tsec->sid, &secdata, &seclen);\n    if (!error) {\n        rc = strcmp("u:r:init:s0", secdata);\n        security_release_secctx(secdata, seclen);\n        if (rc == 0 && new_tsec->sid == ksu_sid)\n            return 0;\n    }\n#endif' security/selinux/hooks.c
        fi

        if grep -q "security_secid_to_secctx" "security/selinux/hooks.c"; then
            echo "[+] security/selinux/hooks.c Patched!"
            echo "[+] Count: $(grep -c "security_secid_to_secctx" "security/selinux/hooks.c")"
        else
            fail "security/selinux/hooks.c patch failed for unknown reasons."
        fi

        if grep -rq --include="*.c" --include="*.h" "ksu_hide_setprocattr" "drivers/kernelsu/" >/dev/null 2>&1; then
            if [ "$FIRST_VERSION" -lt 4 ] && [ "$SECOND_VERSION" -lt 19 ]; then
                echo "[-] Kernel could not hook ksu_hide_setprocattr, Skipped."

            elif [ "$FIRST_VERSION" -lt 5 ] && [ "$SECOND_VERSION" -lt 10 ]; then
                sed -i '/static int selinux_setprocattr(struct task_struct \*p,/i\#ifdef CONFIG_KSU\nextern int ksu_hide_setprocattr(const char *name, void *value, size_t size);\n#endif\n' security/selinux/hooks.c
            else
                sed -i '/static int selinux_setprocattr(const char \*name, void \*value, size_t size)/i\#ifdef CONFIG_KSU\nextern int ksu_hide_setprocattr(const char *name, void *value, size_t size);\n#endif\n' security/selinux/hooks.c
            fi

            if grep -q "char \*str = value;" "security/selinux/hooks.c"; then
                sed -i '/char \*str = value;/a\#ifdef CONFIG_KSU\n\tksu_hide_setprocattr(name, value, size);\n#endif\n' security/selinux/hooks.c
            else
                sed -i '0,/char \*str = value;/b; /char \*str = value;/a\#ifdef CONFIG_KSU\n    ksu_hide_setprocattr(name, value, size);\n#endif\n' security/selinux/hooks.c
            fi

            if grep -q "ksu_hide_setprocattr" "security/selinux/hooks.c"; then
                echo "[+] security/selinux/hooks.c Part II Patched!"
                echo "[+] Count: $(grep -c "ksu_hide_setprocattr" "security/selinux/hooks.c")"
            else
                fail "security/selinux/hooks.c patch failed for unknown reasons."
            fi
        else
            echo "[-] KernelSU needn't ksu_hide_setprocattr, Skipped."
        fi

        echo "======================================"
        ;;
    ## selinux/ss/services.c
    security/selinux/ss/services.c)
        if grep -q "selinux_state" "security/selinux/include/security.h" >/dev/null 2>&1; then
            echo "[-] Kernel needn't selinux_state fix, Skipped."

        elif [ "$FIRST_VERSION" -lt 5 ] && [ "$SECOND_VERSION" -lt 15 ]; then
            sed -i 's/static DEFINE_RWLOCK(policy_rwlock);/DEFINE_RWLOCK(policy_rwlock);/' security/selinux/ss/services.c

            if ! grep -q "static DEFINE_RWLOCK" "security/selinux/ss/services.c"; then
                echo "[+] security/selinux/ss/services.c Patched!"
            else
                fail "security/selinux/ss/services.c patch failed for unknown reasons."
            fi
        fi

        echo "======================================"
        ;;

    # kernel/ changes
    ## reboot.c
    kernel/reboot.c)
        sed -i '/SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,/i\
#ifdef CONFIG_KSU_SUSFS\
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\
#endif\
' kernel/reboot.c
        sed -i '/int ret = 0;/a\
#ifdef CONFIG_KSU_SUSFS\
    if (system_state == SYSTEM_RUNNING) {\
        ksu_handle_sys_reboot(magic1, magic2, cmd, \&arg);\
    }\
#endif\
' kernel/reboot.c

        if grep -q "ksu_handle_sys_reboot" "kernel/reboot.c"; then
            echo "[+] kernel/reboot.c Patched!"
            echo "[+] Count: $(grep -c "ksu_handle_sys_reboot" "kernel/reboot.c")"
        else
            fail "kernel/reboot.c patch failed for unknown reasons."
        fi

        echo "======================================"
        ;;
    ## sys.c
    kernel/sys.c)
        if grep -rq --include="*.c" --include="*.h" "ksu_handle_setresuid" "drivers/kernelsu/" >/dev/null 2>&1; then

            if grep -q "__sys_setresuid" "kernel/sys.c" >/dev/null 2>&1; then
                sed -i '/^SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)/i\#ifdef CONFIG_KSU\nextern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n#endif\n' kernel/sys.c
                sed -i '/return __sys_setresuid(ruid, euid, suid);/i\#ifdef CONFIG_KSU_SUSFS\n\tif (ksu_handle_setresuid(ruid, euid, suid)) {\n\t\tpr_info("Something wrong with ksu_handle_setresuid()\\\\n");\n\t}\n#endif\n' kernel/sys.c
            else
                sed -i '/^SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)/i\#ifdef CONFIG_KSU\nextern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n#endif\n' kernel/sys.c
                sed -i '0,/\tif ((ruid != (uid_t) -1) && !uid_valid(kruid))/b; /\tif ((ruid != (uid_t) -1) && !uid_valid(kruid))/i\#ifdef CONFIG_KSU_SUSFS\n\tif (ksu_handle_setresuid(ruid, euid, suid)) {\n\t\tpr_info("Something wrong with ksu_handle_setresuid()\\\\n");\n\t}\n#endif' kernel/sys.c
            fi

            if grep -q "ksu_handle_setresuid" "kernel/sys.c"; then
                echo "[+] kernel/sys.c Patched!"
                echo "[+] Count: $(grep -c "ksu_handle_setresuid" "kernel/sys.c")"
            else
                fail "kernel/sys.c patch failed for unknown reasons."
            fi
        else
            echo "[-] KernelSU have no ksu_handle_setresuid, Skipped."
        fi

        echo "======================================"
        ;;

    # include/ changes
    ## linux/seccomp.h
    include/linux/seccomp.h)
        echo "======================================"

        if grep -q "filter_count" "include/linux/seccomp.h" >/dev/null 2>&1; then
            echo "[-] Detected filter_count in kernel, Skipped."
        else
            sed -i '/#include <linux\/thread_info.h>/a\#include <linux\/atomic.h>' include/linux/seccomp.h
            sed -i '/struct seccomp_filter \*filter;/i\ \tatomic_t filter_count;' include/linux/seccomp.h

            if grep -q "filter_count" "include/linux/seccomp.h"; then
                echo "[+] include/linux/seccomp.h Patched!"
                echo "[+] Count: $(grep -c "filter_count" "include/linux/seccomp.h")"
            else
                fail "include/linux/seccomp.h patch failed for unknown reasons."
            fi
        fi

        echo "======================================"
        ;;
    esac

done

if [ "$FAILED" -ne 0 ]; then
    echo "[-] SUSFS inline hook patching FAILED, aborting."
    exit 1
fi
echo "[+] All SUSFS inline hook sections applied successfully."
