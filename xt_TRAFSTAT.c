#define pr_fmt(fmt) KBUILD_MODNAME ", %s: " fmt, __func__ 

#include <linux/version.h>
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/netfilter/x_tables.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/dcache.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/types.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
#include <uapi/linux/sched/types.h>
#endif
#include "xt_TRAFSTAT.h"

#define TRAFSTAT_PROC	    "trafstat"
#define KMALLOC_FLAGS       GFP_ATOMIC | __GFP_ZERO
#define STORAGE_COUNT	    CONFIG_NR_CPUS * 2
#define ONLINE_CPUS         (num_online_cpus())
#define MAX_ENTRIES         1000 * 1000

struct traf_thread {
        struct list_head list;
        __u8 refs;

        bool    entries_warn;
        __u8    bitmask, fast_aggregate;
        char    config_net[32];
        __u32   local_net, traf_policy, min_pkt_spoof;
        __u32   max_entries;
        __u8    dump_prio;

        atomic_t    sample_tcp_s, sample_tcp_a, sample_udp_a,
                    storage_group, seq_cpu, seq_offset, entries;
        atomic64_t  packets_pass, packets_lost;

        struct kmem_cache *traf_cache;

        spinlock_t tree_lock[STORAGE_COUNT];

        struct mutex proc_lock;

        struct rb_root storage[STORAGE_COUNT];
        __u32 storage_count[STORAGE_COUNT];

        struct rb_root spoof;
        int spoof_count;

        struct rb_root rb_ports;
};

struct traf_helper { 
        struct traf_thread *tt; 
};

static LIST_HEAD(tt_list);
static DEFINE_MUTEX(tt_list_lock);


static inline int ports_cmp(traf_ports *this, traf_ports *tp)
{
        int res;

        res = this->data.port - tp->data.port;
        if (res)
                return res;

        res = this->data.direction - tp->data.direction;
        if (res)
                return res;

        return this->data.protocol - tp->data.protocol;
}

static inline traf_ports *ports_search(struct rb_root *root, traf_ports *tp)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		traf_ports *this = rb_entry(node, traf_ports, node);
		int result = ports_cmp(this, tp);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return this;
	}

	return NULL;
}

static inline int ports_insert(struct rb_root *root, traf_ports *tp)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		traf_ports *this = rb_entry(*new, traf_ports, node);
		int result = ports_cmp(this, tp);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else 
                        return 0;
	}

	rb_link_node(&tp->node, parent, new);
	rb_insert_color(&tp->node, root);

	return 1;
}

static inline __u16 ports_even(struct rb_root *root, __u8 direction, 
                __u8 protocol, __u16 port, const struct port_search_helper *psh)
{
	traf_ports tp;

        if (direction) {
                if (protocol == IPPROTO_TCP) {
                        if (!psh->remote.tcp_ports) 
                                return 0;
                        else if (psh->remote.tcp_ports == 65535)
                                return port;
                } else {
                        if (!psh->remote.udp_ports)
                                return 0;
                        else if (psh->remote.udp_ports == 65535)
                                return port;
                }
        } else { 
                if (protocol == IPPROTO_TCP) {
                        if (!psh->local.tcp_ports) 
                                return 0;
                        else if (psh->local.tcp_ports == 65535)
                                return port;
                } else {
                        if (!psh->local.udp_ports)
                                return 0;
                        else if (psh->local.udp_ports == 65535)
                                return port;
                }
        }

	tp.data.direction   = direction;
	tp.data.protocol    = protocol;
	tp.data.port        = port;

	if (ports_search(root, &tp))
		return port;
	else
		return 0;
}

static void ports_free(struct rb_root *root)
{
	struct rb_node *node;
	traf_ports *tp;

	for (node = rb_first(root); node; node = rb_next(node)) {
		tp = rb_entry(node, traf_ports, node);
		rb_erase(&tp->node, root);
		kfree(tp);
	}
}

static inline int storage_cmp(traf_stat *this, traf_stat *ts)
{
        int res;

        res = this->traf.remote_addr - ts->traf.remote_addr;
        if (res)
                return res;

        res = this->traf.local_addr - ts->traf.local_addr;
        if (res)
                return res;

        res = this->traf.remote_port - ts->traf.remote_port;
        if (res)
                return res;

        res = this->traf.local_port - ts->traf.local_port;
        if (res)
                return res;

        return this->traf.protocol - ts->traf.protocol;
}

static inline traf_stat *storage_search(struct rb_root *root, traf_stat *ts)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		traf_stat *this = rb_entry(node, traf_stat, node);
		int result = storage_cmp(this, ts);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return this;
	}

	return NULL;
}

static inline int storage_insert(struct rb_root *root, traf_stat *ts)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		traf_stat *this = rb_entry(*new, traf_stat, node);
		int result = storage_cmp(this, ts);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return 0;
	}

	rb_link_node(&ts->node, parent, new);
	rb_insert_color(&ts->node, root);

	return 1;
}

static void storage_free(struct traf_thread *tt, struct rb_root *root)
{
	struct rb_node *node;
	traf_stat *ts;

	for (node = rb_first(root); node; node = rb_next(node)) {
		ts = rb_entry(node, traf_stat, node);
		rb_erase(&ts->node, root);
		kmem_cache_free(tt->traf_cache, ts);
                atomic_dec(&tt->entries);
	}
}

static inline void process_packet(net_options *net_opts, 
                                    const struct xt_TRAFSTAT_info *info)
{
        struct traf_thread *tt = info->tt;
	traf_stat ts, *found, *new;
	__u16 storage_id;
	__u32 source_net = net_opts->ip->saddr << tt->bitmask;

        storage_id = raw_smp_processor_id() + 
                    ((atomic_read(&tt->storage_group)) ? ONLINE_CPUS : 0);

        memset(&ts, 0, sizeof(ts));
	if (source_net == tt->local_net) {
		ts.traf.local_addr  = net_opts->ip->saddr;
		ts.traf.remote_addr = net_opts->ip->daddr;
		ts.traf.local_port  = net_opts->local_port;
		ts.traf.remote_port = net_opts->remote_port;
	} else {
		ts.traf.local_addr  = net_opts->ip->daddr;
		ts.traf.remote_addr = net_opts->ip->saddr;
		ts.traf.local_port  = net_opts->remote_port;
		ts.traf.remote_port = net_opts->local_port;
	}

        ts.traf.protocol = net_opts->ip->protocol;
        if (likely(ts.traf.protocol == IPPROTO_TCP || 
                        ts.traf.protocol == IPPROTO_UDP)) {
		ts.traf.local_port  = ports_even(&tt->rb_ports, 0, 
                            ts.traf.protocol, ts.traf.local_port, &info->psh);
		ts.traf.remote_port = ports_even(&tt->rb_ports, 1, 
                            ts.traf.protocol, ts.traf.remote_port, &info->psh);
	}

        if (unlikely(!spin_trylock(&tt->tree_lock[storage_id]))) {
		atomic64_inc(&tt->packets_lost);
		return;
	}

	found = storage_search(&tt->storage[storage_id], &ts);
	if (likely(found)) {
		found->stat.syn_count += net_opts->syn_flag;
		if (source_net == tt->local_net) {
			found->stat.local_pkt   += 1;
			found->stat.local_data  += net_opts->pkt_len;
		} else {
			found->stat.remote_pkt  += 1;
			found->stat.remote_data += net_opts->pkt_len;
		}
                atomic64_inc(&tt->packets_pass);
	} else {
                if (atomic_add_return(1, &tt->entries) >= tt->max_entries) {
                        if (!tt->entries_warn) {
                                tt->entries_warn = true;
                                pr_warn("local net: %s, storages exceed %u " 
                                    "entries\n", tt->config_net, 
                                                 tt->max_entries);
                        }
                        atomic64_inc(&tt->packets_lost);
                        atomic_dec(&tt->entries);
                        goto unlocks;
                }

                new = kmem_cache_alloc(tt->traf_cache, KMALLOC_FLAGS);
                if (unlikely(!new)) {
                        pr_warn("local net: %s, error in kmem_cache_alloc\n",
                                tt->config_net);
                        atomic64_inc(&tt->packets_lost);
                        goto unlocks;
                }

                new->traf.local_addr  = ts.traf.local_addr;
                new->traf.remote_addr = ts.traf.remote_addr;
                new->traf.local_port  = ts.traf.local_port;
                new->traf.remote_port = ts.traf.remote_port;
                new->traf.protocol    = ts.traf.protocol;

		new->stat.syn_count  = net_opts->syn_flag;
		if (source_net == tt->local_net) {
			new->stat.local_pkt   = 1;
			new->stat.local_data  = net_opts->pkt_len;
		} else {
			new->stat.remote_pkt  = 1;
			new->stat.remote_data = net_opts->pkt_len;
		}

                if (unlikely(!storage_insert(&tt->storage[storage_id], new))) {
			pr_warn("local net: %s, error in storage_insert\n",
                                tt->config_net);
                        atomic64_inc(&tt->packets_lost);
                        kmem_cache_free(tt->traf_cache, new);
                        atomic_dec(&tt->entries);
                } else {
                        atomic64_inc(&tt->packets_pass);
			tt->storage_count[storage_id]++;
                }
	}
unlocks:
        spin_unlock(&tt->tree_lock[storage_id]);
}

static unsigned int trafstat_tg(struct sk_buff *skb,
                                const struct xt_action_param *par)
{
	const struct xt_TRAFSTAT_info *info = par->targinfo;
        struct traf_thread *tt = info->tt;
	net_options *net_opts, n_opts;

	net_opts = &n_opts;
	memset(net_opts, 0, sizeof(net_options));

	net_opts->pkt_data = skb->data;
	net_opts->pkt_len  = skb->len;
	net_opts->ip = (struct iphdr *) skb->data;

	if (likely(net_opts->ip->protocol == IPPROTO_TCP)) {
                if (info->sample_tcp_a) {
                        if (atomic_inc_return(&tt->sample_tcp_a) !=
                                        info->sample_tcp_a) {
                                atomic64_inc(&tt->packets_lost);
                                return tt->traf_policy;
                        } else {
                                atomic_set(&tt->sample_tcp_a, 0);
                        }
                }

		net_opts->tcp = (struct tcphdr *)
		                (skb->data + (net_opts->ip->ihl << 2));
		net_opts->syn_flag = net_opts->tcp->syn && !net_opts->tcp->ack;

                if (info->sample_tcp_s && net_opts->syn_flag) {
                        if (atomic_inc_return(&tt->sample_tcp_s) !=
                                        info->sample_tcp_s) {
                                atomic64_inc(&tt->packets_lost);
                                return tt->traf_policy;
                        } else {
                                atomic_set(&tt->sample_tcp_s, 0);
                        }
                }

		net_opts->local_port  = net_opts->tcp->source;
		net_opts->remote_port = net_opts->tcp->dest;
	} else if (likely(net_opts->ip->protocol == IPPROTO_UDP)) {
                if (info->sample_udp_a) {
                        if (atomic_inc_return(&tt->sample_udp_a) !=
                                        info->sample_udp_a) {
                                atomic64_inc(&tt->packets_lost);
                                return tt->traf_policy;
                        } else {
                                atomic_set(&tt->sample_udp_a, 0);
                        }
                }

		net_opts->udp = (struct udphdr *)
		                (skb->data + (net_opts->ip->ihl << 2));
		net_opts->local_port  = net_opts->udp->source;
		net_opts->remote_port = net_opts->udp->dest;
	}

	process_packet(net_opts, info);

	return tt->traf_policy;
}

static inline struct traf_thread *tt_by_config_net(char *config_net)
{
        struct traf_thread *tt;

        list_for_each_entry(tt, &tt_list, list)
                if (!strcmp(tt->config_net, config_net))
                        return tt;

        return NULL;
}

static inline traf_stat *aggregate_data(
                struct traf_thread *tt, traf_stat *ts, __u16 storage_id)
{
#ifdef DEBUG_AGGREGATE
        __u16 hits = 0;
#endif
        traf_stat *fnd;

        for (++storage_id;
                    storage_id < ONLINE_CPUS + (atomic_read(&tt->seq_offset));
                    storage_id++) {
                if (tt->storage_count[storage_id] &&
                                spin_trylock(&tt->tree_lock[storage_id])) {
                        fnd = storage_search(&tt->storage[storage_id], ts);
                        if (fnd != NULL) {
                                ts->stat.local_pkt   += fnd->stat.local_pkt;
                                ts->stat.remote_pkt  += fnd->stat.remote_pkt;
                                ts->stat.local_data  += fnd->stat.local_data;
                                ts->stat.remote_data += fnd->stat.remote_data;
                                ts->stat.syn_count   += fnd->stat.syn_count;
                                tt->storage_count[storage_id]--;
                                rb_erase(&fnd->node, &tt->storage[storage_id]);
                                kmem_cache_free(tt->traf_cache, fnd);
                                atomic_dec(&tt->entries);

#ifdef DEBUG_AGGREGATE
                                hits++;
#endif
                                if (tt->fast_aggregate) {
                                        spin_unlock(&tt->tree_lock[storage_id]);
                                        return ts;
                                }
                        }
                        spin_unlock(&tt->tree_lock[storage_id]);
                }
        }
#ifdef DEBUG_AGGREGATE
        if (hits > 1)
                pr_info("%u:%u<->%u:%u, hits: %u\n",
                        ntohl(ts->traf.local_addr),
                        ntohs(ts->traf.local_port),
                        ntohl(ts->traf.remote_addr)
                        ntohs(ts->traf.remote_port),
                        hits);
#endif
        return ts;
}

static inline int add_spoofed(struct traf_thread *tt, traf_stat *ts) 
{
        traf_stat *new, *fnd;

        if (tt->min_pkt_spoof && tt->min_pkt_spoof > ts->stat.remote_pkt) {
                ts->traf.remote_addr = 0;
                ts->traf.remote_port = 0;
                fnd = storage_search(&tt->spoof, ts);
                if (likely(fnd)) {
                        fnd->stat.remote_pkt    += ts->stat.remote_pkt;
                        fnd->stat.remote_data   += ts->stat.remote_data;
                        fnd->stat.local_pkt     += ts->stat.local_pkt;
                        fnd->stat.local_data    += ts->stat.local_data;
                        fnd->stat.syn_count     += ts->stat.syn_count;
                } else {
                        new = kmem_cache_alloc(tt->traf_cache,
                                                GFP_KERNEL | __GFP_ZERO);
                        if (unlikely(!new)) {
                                pr_warn("error in kmalloc for new\n");
                                return 0;
                        }
                        new->traf.protocol      = ts->traf.protocol;
                        new->traf.local_addr    = ts->traf.local_addr;
                        new->traf.local_port    = ts->traf.local_port;
                        new->stat.remote_pkt    = ts->stat.remote_pkt;
                        new->stat.remote_data   = ts->stat.remote_data;
                        new->stat.local_pkt     = ts->stat.local_pkt;
                        new->stat.local_data    = ts->stat.local_data;
                        new->stat.syn_count     = ts->stat.syn_count;
                        if (unlikely(!storage_insert(&tt->spoof, new))) {
                                pr_warn("error in storage_insert\n");
                                kmem_cache_free(tt->traf_cache, new);
                                return 0;
                        }
                        tt->spoof_count++;
                }
                return 1;
        }

        return 0;
}

static traf_stat *get_node(struct traf_helper *th, loff_t *pos)
{
        struct traf_thread *tt = th->tt;
	struct rb_node *node = NULL, *prev_node = NULL;
	traf_stat *ts = NULL;
	__u16 cpu, storage_id;

        for (cpu = atomic_read(&tt->seq_cpu); cpu < ONLINE_CPUS; cpu++) {
                storage_id = cpu + (atomic_read(&tt->seq_offset));
		if (tt->storage_count[storage_id]) {

			spin_lock(&tt->tree_lock[storage_id]);

			prev_node = rb_first(&tt->storage[storage_id]);
			if (!*pos || cpu != atomic_read(&tt->seq_cpu)) {
				node = prev_node;
			} else if (prev_node) {
				node = rb_next(prev_node);
				ts = rb_entry(prev_node, traf_stat, node);
				rb_erase(prev_node, &tt->storage[storage_id]);
                                kmem_cache_free(tt->traf_cache, ts);
				tt->storage_count[storage_id]--;
                                atomic_dec(&tt->entries);
			}

			spin_unlock(&tt->tree_lock[storage_id]);

			if (node) {
                                ts = rb_entry(node, traf_stat, node);

                                if (tt->min_pkt_spoof && 
                                    tt->min_pkt_spoof > ts->stat.remote_pkt)
                                        return ts;

                                return aggregate_data(tt, ts, storage_id);
                        }
                } else {
			atomic_inc(&tt->seq_cpu);
		}
	}

        if (tt->spoof_count) {
                if (tt->spoof_count > 0) {
                        tt->spoof_count = -tt->spoof_count;
                        node = rb_first(&tt->spoof);
                        ts = rb_entry(node, traf_stat, node);
                        return ts;
                }
                if (tt->spoof_count == -1) {
                        tt->spoof_count = 0;
                        node = rb_first(&tt->spoof);
                        ts = rb_entry(node, traf_stat, node);
                        rb_erase(node, &tt->spoof);
                        kmem_cache_free(tt->traf_cache, ts);
                        return NULL;
                }
                tt->spoof_count++;
                prev_node = rb_first(&tt->spoof);
                node = rb_next(prev_node);
                ts = rb_entry(prev_node, traf_stat, node);
                rb_erase(prev_node, &tt->spoof);
                kmem_cache_free(tt->traf_cache, ts);
                ts = rb_entry(node, traf_stat, node);
                return ts;
        }

	return NULL;
}

static void *trafstat_seq_start(struct seq_file *seq, loff_t *pos)
{
	*pos = 0;
	return get_node((struct traf_helper *) seq->private, pos);
}

static void *trafstat_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return get_node((struct traf_helper *) seq->private, pos);
}

static int trafstat_seq_show(struct seq_file *seq, void *v)
{
        struct traf_helper *th = (struct traf_helper *) seq->private;
        struct traf_thread *tt = th->tt;
        traf_stat *ts = (traf_stat *) v;

        if (add_spoofed(tt, ts))
                return 0;

        seq_printf(seq, "%u,%u,%u,%u,%u,%u,%u,%llu,%llu,%u\n",
                ts->traf.protocol, ntohl(ts->traf.local_addr),
                ntohl(ts->traf.remote_addr), ntohs(ts->traf.local_port),
                ntohs(ts->traf.remote_port), ts->stat.local_pkt,
                ts->stat.remote_pkt, ts->stat.local_data,
                ts->stat.remote_data, ts->stat.syn_count);

        return 0;
}

static void trafstat_seq_stop(struct seq_file *seq, void *v) 
{
        struct traf_helper *th = (struct traf_helper *) seq->private;
        struct traf_thread *tt = th->tt;

        tt->entries_warn = false;
        if (mutex_is_locked(&tt->proc_lock))
                mutex_unlock(&tt->proc_lock);
}

static const struct seq_operations trafstat_seq_ops = {
        .start = trafstat_seq_start,
        .next  = trafstat_seq_next,
        .show  = trafstat_seq_show,
        .stop  = trafstat_seq_stop,
};

static int trafstat_seq_open(struct inode *inode, struct file *file)
{
        struct traf_thread *tt;
        struct traf_helper *th;
        char *tmp, *pathname, *config_net;
        struct path path;
        struct seq_file *s;
        //__u32 local_net;
        int ret;

        ret = seq_open(file, &trafstat_seq_ops);
        if (ret) {
                pr_err("error in seq_open\n");
                return ret;
        }

        tmp = (char *) __get_free_page(GFP_KERNEL);
        if (!tmp) {
                pr_err("error in __get_free_page\n");
                return -ENOMEM;
        }

        if (!spin_trylock(&file->f_lock)) {
                pr_err("busy in spin_trylock, abort\n");
                goto err1;
        }

        path = file->f_path;
        path_get(&file->f_path);
        pathname = d_path(&path, tmp, PAGE_SIZE);
        path_put(&path);

        if (IS_ERR(pathname)) {
                pr_err("error in pathname\n");
                goto err2;
        }

        config_net = strrchr(pathname, '/') + 1;
        /*
        ret = kstrtou32(tid, 0, &local_net);
        if (ret < 0) {
                pr_err("error in kstrtou32\n");
                goto err2;
        }
        */

        tt = tt_by_config_net(config_net);
        if (!tt) {
                pr_err("local net: %s, error in tt_by_config_net\n", 
                    config_net);
                goto err2;
        }
        
        if (tt->dump_prio) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
                sched_set_fifo(current);
#else

                struct sched_param param = { .sched_priority = MAX_RT_PRIO / 2 };
                //struct sched_param param = { .sched_priority = tt->dump_prio };
                sched_setscheduler(current, SCHED_RR, &param);
#endif
        }
        
        if (!mutex_trylock(&tt->proc_lock)) {
                pr_err("local net: %s, proc file is busy\n", config_net);
                goto err2;
        }

        tt->spoof_count = 0;
	atomic_set(&tt->storage_group, atomic_read(&tt->storage_group) ? 0 : 1);
	atomic_set(&tt->seq_offset, (atomic_read(&tt->storage_group)) ? 
                                            0 : ONLINE_CPUS);

        s = file->private_data;
        s->private = kzalloc(sizeof(struct traf_helper), GFP_KERNEL);
        if (!s->private) {
                pr_err("local net: %s, error in kzalloc\n", config_net);
                goto err2;
        }

        th = s->private;
        th->tt = tt;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
        pr_info("local net: %s; passed/lost packets: %llu/%llu, cpu: %u\n",

#else
        pr_info("local net: %s; passed/lost packets: %lu/%lu, cpu: %u\n",
#endif
	                tt->config_net, atomic64_read(&tt->packets_pass), 
                        atomic64_read(&tt->packets_lost), 
                        raw_smp_processor_id());

        atomic_set(&tt->seq_cpu, 0);
        atomic64_set(&tt->packets_pass, 0);
        atomic64_set(&tt->packets_lost, 0);

        spin_unlock(&file->f_lock);

        free_page((__u64) tmp);

        return 0;

err2:
        spin_unlock(&file->f_lock);
err1:
        free_page((__u64) tmp);

        return -EPERM;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,5,0)
static const struct proc_ops trafstat_file_ops = {
	.proc_open      = trafstat_seq_open,
	.proc_read      = seq_read,
	.proc_lseek     = seq_lseek,
	.proc_release   = seq_release_private,
};
#else
static const struct file_operations trafstat_file_ops = {
       .owner   = THIS_MODULE,
       .open    = trafstat_seq_open,
       .read    = seq_read,
       .llseek  = seq_lseek,
       .release = seq_release_private,
};
#endif

static int build_ports(struct rb_root *rb_ports, __u8 direction, __u8 protocol,
			const __u16 ports[XT_TRAFSTAT_PORTS])
{
	traf_ports *tp;
	__u16 i;

        for (i = 0; i < XT_TRAFSTAT_PORTS; i++) {
               if (ports[i] == 0 || ports[i] == 65535)
                        return 0;

                tp = kzalloc(sizeof(traf_ports), GFP_KERNEL);
                if (!tp) {
                        pr_err("error in kzalloc\n");
                        return -ENOMEM;
                }

                tp->data.direction  = direction;
                tp->data.protocol   = protocol;
                tp->data.port       = htons(ports[i]);

                if (!ports_insert(rb_ports, tp))
                        kfree(tp);
        }

        return 0;
}

static struct traf_thread *create_tt(struct xt_TRAFSTAT_info *info)
{
        struct traf_thread *tt;
        char tmp[32];
        int i;
        
        tt = kzalloc(sizeof(struct traf_thread), GFP_KERNEL);

        if (!tt) {
                pr_err("error in kzalloc\n");
                goto err1;
        }

        memset(&tmp, 0, sizeof(tmp));
        snprintf(tmp, sizeof(tmp) - 1, "trafstat_%s", info->config_net);

        tt->traf_cache = kmem_cache_create(tmp, sizeof(traf_stat), 0, 
                                        SLAB_RECLAIM_ACCOUNT, NULL);
        if (!tt->traf_cache) {
                pr_err("error in kmem_cache_create\n"); 
                goto err2;
        }

	for (i = 0; i < STORAGE_COUNT; i++) {
                spin_lock_init(&tt->tree_lock[i]);
                tt->storage[i] = RB_ROOT;
	}

        mutex_init(&tt->proc_lock);

        memcpy(tt->config_net, info->config_net, sizeof(tt->config_net));
        tt->rb_ports        = RB_ROOT;
        tt->spoof           = RB_ROOT;
        tt->refs            = 1;
        tt->local_net       = info->local_net;
        tt->bitmask         = info->bitmask;
        tt->traf_policy     = info->traf_policy;
        tt->max_entries     = (info->max_entries) ? 
                                    info->max_entries * 1000 : MAX_ENTRIES;
        tt->min_pkt_spoof   = info->min_pkt_spoof;
        tt->fast_aggregate  = info->fast_aggregate;
        tt->dump_prio       = info->dump_prio;

	if (build_ports(&tt->rb_ports, 0, IPPROTO_TCP, info->local_tcp_ports))
                goto err3;
	if (build_ports(&tt->rb_ports, 0, IPPROTO_UDP, info->local_udp_ports))
                goto err3;
	if (build_ports(&tt->rb_ports, 1, IPPROTO_TCP, info->remote_tcp_ports))
                goto err3;
	if (build_ports(&tt->rb_ports, 1, IPPROTO_UDP, info->remote_udp_ports))
                goto err3;

        memset(&tmp, 0, sizeof(tmp));
        snprintf(tmp, sizeof(tmp) - 1, "%s/%s", 
            TRAFSTAT_PROC, info->config_net);
        if (!proc_create(tmp, 0, NULL, &trafstat_file_ops)) {
                pr_err("error in proc_create\n");
                goto err3;
        }

        INIT_LIST_HEAD(&tt->list);

        list_add_tail(&tt->list, &tt_list);

        return tt;

err3:
        ports_free(&tt->rb_ports);
err2:
        kfree(tt);
err1:
        return NULL;
}

static int trafstat_tg_check(const struct xt_tgchk_param *par)
{
        struct xt_TRAFSTAT_info *info = par->targinfo;
        struct traf_thread *tt;

        mutex_lock(&tt_list_lock);

        tt = tt_by_config_net((char *)&info->config_net);
        if (tt) {
                tt->refs++;
        } else {
                tt = create_tt(info);
                if (!tt) {
                        pr_err("local net: %s, error in create_tt\n",
                                        info->config_net);
                        mutex_unlock(&tt_list_lock);
                        return -ENOMEM;
                }
        }
        info->tt = tt;

        mutex_unlock(&tt_list_lock);

        return 0;
}

static void destroy_tt(struct traf_thread *tt)
{
        char tmp[64];
	int i;

        memset(&tmp, 0, sizeof(tmp));
        snprintf(tmp, sizeof(tmp) - 1, "%s/%s", TRAFSTAT_PROC, tt->config_net);
        remove_proc_entry(tmp, NULL);

        ports_free(&tt->rb_ports);

	for (i = 0; i < STORAGE_COUNT; i++) {
                spin_lock(&tt->tree_lock[i]);
                storage_free(tt, &tt->storage[i]);
                spin_unlock(&tt->tree_lock[i]);
	}

        storage_free(tt, &tt->spoof);

        kmem_cache_destroy(tt->traf_cache);

        list_del(&tt->list);

        kfree(tt);
}

static void trafstat_tg_destroy(const struct xt_tgdtor_param *par)
{
        struct xt_TRAFSTAT_info *info = par->targinfo;
        struct traf_thread *tt = info->tt;

        if (!tt) {
                pr_err("local net: %s, no traf_thread\n", info->config_net);
                return;
        }

        mutex_lock(&tt_list_lock);

        if (!(--tt->refs))
                destroy_tt(tt);

        mutex_unlock(&tt_list_lock);
}

static struct xt_target trafstat_tg_reg __read_mostly = {
	.name	    = "TRAFSTAT",
	.revision   = 0,
	.family	    = NFPROTO_IPV4,
	.target	    = trafstat_tg,
        .checkentry = trafstat_tg_check,
        .destroy    = trafstat_tg_destroy,
	.targetsize = sizeof(struct xt_TRAFSTAT_info),
	.me	    = THIS_MODULE,
};

static int __init trafstat_tg_init(void)
{
        int ret;

        if (!proc_mkdir(TRAFSTAT_PROC, NULL)) {
                pr_err("error in proc_mkdir %s\n", TRAFSTAT_PROC);
                goto err1;
        }

        ret = xt_register_target(&trafstat_tg_reg);
        if (ret < 0) {
                pr_err("error in xt_register_target\n");
                goto err2;
        }

        return 0;

err2:
        remove_proc_entry(TRAFSTAT_PROC, NULL);
err1:
        return -ENOMEM;
}

static void __exit trafstat_tg_exit(void)
{
        remove_proc_entry(TRAFSTAT_PROC, NULL);
        xt_unregister_target(&trafstat_tg_reg);
}

module_init(trafstat_tg_init);
module_exit(trafstat_tg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("gglluukk");
MODULE_DESCRIPTION("Xtables: traffic statistics");
MODULE_ALIAS("xt_TRAFSTAT");
MODULE_ALIAS("ipt_TRAFSTAT");
MODULE_VERSION("0.30");
