#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <xtables.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/version.h>
#include "xt_TRAFSTAT.h"

enum {
	O_LOCAL_NET = 0,
	O_LOCAL_TCP_PORTS,
	O_LOCAL_UDP_PORTS,
	O_REMOTE_TCP_PORTS,
	O_REMOTE_UDP_PORTS,
        O_MAX_ENTRIES,
	O_TRAF_POLICY,
        O_MIN_SPOOF,
        O_SAMPLE_TCP_SYN,
        O_SAMPLE_TCP_ANY,
        O_SAMPLE_UDP_ANY,
        O_FAST_AGGREGATE,
        O_DUMP_PRIO,
};

static const struct xt_option_entry TRAFSTAT_opts[] = {
	{.name = "local-net",           .id = O_LOCAL_NET,
	 .type = XTTYPE_HOSTMASK, .flags = XTOPT_MAND},
	{.name = "local-tcp-ports",     .id = O_LOCAL_TCP_PORTS,
	 .type = XTTYPE_STRING},
	{.name = "local-udp-ports",     .id = O_LOCAL_UDP_PORTS,
	 .type = XTTYPE_STRING},
	{.name = "remote-tcp-ports",    .id = O_REMOTE_TCP_PORTS,
	 .type = XTTYPE_STRING},
	{.name = "remote-udp-ports",    .id = O_REMOTE_UDP_PORTS,
	 .type = XTTYPE_STRING},
	{.name = "max-entries",         .id = O_MAX_ENTRIES,
	 .type = XTTYPE_UINT32},
        {.name = "traf-policy",         .id = O_TRAF_POLICY,
	 .type = XTTYPE_STRING},
	{.name = "min-pkt-spoof",       .id = O_MIN_SPOOF,
	 .type = XTTYPE_UINT32},
	{.name = "sample-tcp-syn",      .id = O_SAMPLE_TCP_SYN,
	 .type = XTTYPE_UINT32},
	{.name = "sample-tcp-any",      .id = O_SAMPLE_TCP_ANY,
	 .type = XTTYPE_UINT32},
	{.name = "sample-udp-any",      .id = O_SAMPLE_UDP_ANY,
	 .type = XTTYPE_UINT32},
	{.name = "fast-aggregate",      .id = O_FAST_AGGREGATE,
	 .type = XTTYPE_NONE},
	{.name = "dump-priority",       .id = O_DUMP_PRIO,
	 .type = XTTYPE_UINT32},
	XTOPT_TABLEEND
};

static void TRAFSTAT_help(void)
{
	printf("TRAFSTAT target options ('*' marks default values):\n"
	       "  --local-net address/netmask\n"
	       "    designates local IP network, e.g.: 192.168.0.1/24\n"
	       "  --local-tcp-ports {all|none|port[,port,port]}\n"
	       "    statistics on all, none* or any %d local TCP ports\n"
	       "  --local-udp-ports {all|none|port[,port,port]}\n"
	       "    statistics on all, none* or any %d local UDP ports\n"
	       "  --remote-tcp-ports {all|none|port[,port,port]}\n"
	       "    statistics on all, none* or any %d remote TCP ports\n"
	       "  --remote-udp-ports {all|none|port[,port,port]}\n"
	       "    statistics on all, none* or any %d remote UDP ports\n"
               "  --max-entries {in thousands}\n"
               "    set limit for storages' entries\n"
	       "  --traf-policy {accept|continue|drop}\n"
	       "    policy for packets: accept, continue* or drop\n"
               "  --sample-tcp-syn {unsigned int}\n"
               "    perform sampling for TCP SYN packets or 0* if not\n"
               "  --sample-tcp-any {unsigned int}\n"
               "    perform sampling for all TCP packets or 0* if not\n"
               "  --sample-udp-any {unsigned int}\n"
               "    perform sampling for all UDP packets or 0* if not\n"
               "  --min-pkt-spoof {unsigned int}\n"
               "    aggregate data in entry where remote/local IP = 0\n"
               "    if remote packet count is less than min-pkt-spoof\n"
               "  --fast-aggregate\n"
               "    faster by aggregating first concurrence at storages\n"
               "  --dump-priority\n"
               "    priority for dump process, values: 0 < x < 100\n\n",
                    XT_TRAFSTAT_PORTS, XT_TRAFSTAT_PORTS, 
                    XT_TRAFSTAT_PORTS, XT_TRAFSTAT_PORTS);
}

static int mask2bit(uint32_t netmask)
{
	uint32_t bm, bits;

	netmask = ntohl(netmask);
	for (bits = 0, bm = 0x80000000; netmask & bm; netmask <<= 1)
		bits++;
	if (netmask)
		return -1;
	return bits;
}

static void parse_multi_ports(const char *portstring, uint16_t *ports, 
                                char *proto, struct port_search_helper *psh, 
                                bool is_remote, bool is_tcp)
{
	char *buffer, *cp, *next;
	__u16 set_port, i;

	buffer = strdup(portstring);
	if (!buffer)
		xtables_error(OTHER_PROBLEM, "strdup failed");

	if (strcasecmp(buffer, "none") == 0) {
                set_port = 0;
                goto out;
        } 

	if (strcasecmp(buffer, "all") == 0) {
		set_port = ports[0] = 65535;
		goto out;
	}

        set_port = 12345;
	for (cp = buffer, i = 0; cp && i < XT_TRAFSTAT_PORTS; cp = next, i++) {
		next = strchr(cp, ',');
		if (next)
			*next++ = '\0';
		ports[i] = xtables_parse_port(cp, proto);
		if (!ports[i])
			xtables_error(PARAMETER_PROBLEM, "error port set");
	}
	if (cp)
		xtables_error(PARAMETER_PROBLEM, "too many ports specified");
out:
        if (is_remote) {
                if (is_tcp) 
                        psh->remote.tcp_ports = set_port;
                else
                        psh->remote.udp_ports = set_port;           
        } else {
                if (is_tcp)
                        psh->local.tcp_ports = set_port;
                else
                        psh->local.udp_ports = set_port;
        }

	free(buffer);
}

static void TRAFSTAT_parse(struct xt_option_call *cb)
{
	struct xt_TRAFSTAT_info *info = cb->data;
	
        xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_LOCAL_NET:
                memcpy(&info->addr, &cb->val.haddr, sizeof(cb->val.haddr));
		memcpy(&info->mask, &cb->val.hmask, sizeof(cb->val.hmask));
		info->bitmask = 32 - mask2bit(info->mask.ip);
		info->local_net = info->addr.ip << info->bitmask;
                snprintf(info->config_net, sizeof(info->config_net), "%s_%s",
                    xtables_ipaddr_to_numeric(&info->addr.in), 
                    (!info->bitmask) ? "32" : 
                        xtables_ipmask_to_numeric(&info->mask.in)+1);
		break;
	case O_LOCAL_TCP_PORTS:
		parse_multi_ports(cb->arg, info->local_tcp_ports, 
                                    "tcp", &info->psh, 0, 1);
		break;
	case O_LOCAL_UDP_PORTS:
		parse_multi_ports(cb->arg, info->local_udp_ports, 
                                    "udp", &info->psh, 0, 0);
		break;
	case O_REMOTE_TCP_PORTS:
		parse_multi_ports(cb->arg, info->remote_tcp_ports, 
                                    "tcp", &info->psh, 1, 1);
		break;
	case O_REMOTE_UDP_PORTS:
		parse_multi_ports(cb->arg, info->remote_udp_ports, 
                                    "udp", &info->psh, 1, 0);
		break;
 	case O_MAX_ENTRIES:
                info->max_entries = atoi(cb->arg);
		break;
	case O_TRAF_POLICY:
		if (strcasecmp(cb->arg, "accept") == 0)
			info->traf_policy = NF_ACCEPT;
		if (strcasecmp(cb->arg, "drop") == 0)
			info->traf_policy = NF_DROP;
		break;
 	case O_MIN_SPOOF:
                info->min_pkt_spoof = atoi(cb->arg);
		break;
 	case O_SAMPLE_TCP_SYN:
                info->sample_tcp_s = atoi(cb->arg);
		break;
 	case O_SAMPLE_TCP_ANY:
                info->sample_tcp_a = atoi(cb->arg);
		break;
 	case O_SAMPLE_UDP_ANY:
                info->sample_udp_a = atoi(cb->arg);
		break;
 	case O_FAST_AGGREGATE:
                info->fast_aggregate = 1;
		break;
 	case O_DUMP_PRIO:
                info->dump_prio = atoi(cb->arg);
                if (info->dump_prio > 100)
                        xtables_error(PARAMETER_PROBLEM, 
                            "priority can't be set more than 100");
		break;
	}
}

static const char *port_to_service(char *opt, int port)
{
	const struct servent *service;
	char proto[4];

	if (strstr(opt, "tcp"))
		sprintf(proto, "%s", "tcp");
	else if (strstr(opt, "udp"))
		sprintf(proto, "%s", "udp");
	else
		return NULL;

	if ((service = getservbyport(htons(port), proto)))
		return service->s_name;

	return NULL;
}

static void print_port(char *opt, uint16_t port, int numeric, int print)
{
	const char *service;

	if (numeric || !print || (service = port_to_service(opt, port)) == NULL)
		printf("%u", port);
	else
		printf("%s", service);
}

#define FANCY_PRINT
static void print_ports(char *opt, const __u16 ports[XT_TRAFSTAT_PORTS],
		            int numeric, int print)
{
	__u16 i;

	if (ports[0]) {
#ifdef FANCY_PRINT
		if (print)
			printf(" %s:", opt);
		else
#endif
			printf(" --%s ", opt);

		if (ports[0] == 65535) {
			printf("all");
		} else {
			for (i = 0; i < XT_TRAFSTAT_PORTS; i++) {
				if (ports[i]) {
					print_port(opt, ports[i], numeric,
						   print);
					if (i < XT_TRAFSTAT_PORTS && 
                                                    ports[i + 1])
						printf(",");
				} else {
					break;
				}
			}
		}
	}
}

static void __trafstat_print(const void *ip, 
                                const struct xt_entry_target *target,
		                int numeric, int print)
{
	const struct xt_TRAFSTAT_info *info = (const void *)target->data;

        if (info->addr.in.s_addr) {
#ifdef FANCY_PRINT
	        if (print)
		        printf(" local-net:");
	        else
#endif
		        printf(" --local-net ");
	        printf("%s%s", xtables_ipaddr_to_numeric(&info->addr.in),
	                        xtables_ipmask_to_numeric(&info->mask.in));
        }

	print_ports("local-tcp-ports", info->local_tcp_ports, numeric, print);
	print_ports("local-udp-ports", info->local_udp_ports, numeric, print);
	print_ports("remote-tcp-ports", info->remote_tcp_ports, numeric, print);
	print_ports("remote-udp-ports", info->remote_udp_ports, numeric, print);

        if (info->max_entries) {
#ifdef FANCY_PRINT
                if (print)
                        printf(" max-entries:%uK", info->max_entries);
                else
#endif
                        printf(" --max-entries %u", info->max_entries);
        }

	if (info->traf_policy != XT_CONTINUE) {
#ifdef FANCY_PRINT
		if (print) {
                        if (!info->traf_policy)
			        printf(" traf-policy:drop");
                        else
                                printf(" traf-policy:accept");

                } else
#endif
                        {
                        if (!info->traf_policy)
                                printf(" --traf-policy drop");
                        else
                                printf(" --traf-policy accept");
                }
	}

        if (info->min_pkt_spoof) {
                if (print)
                        printf(" min-pkt-spoof:%u", info->min_pkt_spoof);
                else
                        printf(" --min-pkt-spoof %u", info->min_pkt_spoof);                       
        }

        if (info->sample_tcp_s) {
                if (print)
                        printf(" sample-tcp-syn:%u", info->sample_tcp_s);
                else
                        printf(" --sample-tcp-syn %u", info->sample_tcp_s);
        }

        if (info->sample_tcp_a) {
                if (print)
                        printf(" sample-tcp-any:%u", info->sample_tcp_a);
                else
                        printf(" --sample-tcp-any %u", info->sample_tcp_a);
        }

        if (info->sample_udp_a) {
                if (print)
                        printf(" sample-udp-any:%u", info->sample_udp_a);
                else
                        printf(" --sample-udp-any %u", info->sample_udp_a);
        }

        if (info->fast_aggregate) {
                if (print)
                        printf(" fast-aggregate");
                else
                        printf(" --fast-aggregate");
        }

        if (info->dump_prio) {
                if (print)
                        printf(" dump-priority:%u", info->sample_udp_a);
                else
                        printf(" --dump-priority %u", info->sample_udp_a);
        }

}

static void TRAFSTAT_print(const void *ip, 
                            const struct xt_entry_target *target, int numeric)
{
	__trafstat_print(ip, target, numeric, 1);
}

static void TRAFSTAT_save(const void *ip, const struct xt_entry_target *target)
{
	__trafstat_print(ip, target, 0, 0);
}

static void TRAFSTAT_init(struct xt_entry_target *t)
{
        struct xt_TRAFSTAT_info *info = (struct xt_TRAFSTAT_info *) t->data;

        memset(info, 0, sizeof(struct xt_TRAFSTAT_info));
        info->traf_policy = XT_CONTINUE;
}

static struct xtables_target trafstat_tg_reg = {
	.family         = NFPROTO_IPV4,
	.name           = "TRAFSTAT",
	.version        = XTABLES_VERSION,
	.revision       = 0,
	.size           = XT_ALIGN(sizeof(struct xt_TRAFSTAT_info)),
	.userspacesize  = offsetof(struct xt_TRAFSTAT_info, tt),
	.help           = TRAFSTAT_help,
	.x6_parse       = TRAFSTAT_parse,
	.x6_options     = TRAFSTAT_opts,
	.print          = TRAFSTAT_print,
	.save           = TRAFSTAT_save,
        .init           = TRAFSTAT_init,
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0))
static __attribute__((constructor)) void echo_tg_ldr(void) {
        xtables_register_target(&trafstat_tg_reg);
}

#else
void _init(void)
{
        xtables_register_target(&trafstat_tg_reg);
}
#endif
