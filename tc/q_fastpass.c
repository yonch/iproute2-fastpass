/*
 * FastPass
 *
 *  Copyright (C) 2013 Jonathan Perry <yonch@yonch.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

#include "kernel-mod/fp_statistics.h"
#include "protocol/fpproto.h"
#include "protocol/stat_print.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... fastpass [ limit PACKETS ] [ flow_limit PACKETS ]\n");
	fprintf(stderr, "              [ buckets NUMBER ] [ rate RATE ]\n");
	fprintf(stderr, "              [ timeslot_mul NUM  ] [ timeslot_shift NUM ]\n");
	fprintf(stderr, "              [ req_cost NSEC ] [ req_bucket NSEC ] [ req_gap NSEC ]\n");
	fprintf(stderr, "              [ ctrl IPADDR ] [ miss_threshold N_TSLOTS ]\n");
	fprintf(stderr, "              [ backlog NSEC ] [ preload N_TSLOTS ]\n");
	fprintf(stderr, "              [ update_timer NSEC ]\n");
}

static unsigned int ilog2(unsigned int val)
{
	unsigned int res = 0;

	val--;
	while (val) {
		res++;
		val >>= 1;
	}
	return res;
}

static int fastpass_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			struct nlmsghdr *n)
{
	unsigned int plimit = ~0U;
	unsigned int flow_plimit = ~0U;
	unsigned int buckets = 0;
	unsigned int data_rate = ~0U;
	unsigned int tslot_len = ~0U;
	unsigned int req_cost = ~0U;
	unsigned int req_bucketlen = ~0U;
	unsigned int req_min_gap = ~0U;
	unsigned int timeslot_mul = ~0U;
	unsigned int timeslot_shift = ~0U;
	unsigned int miss_threshold = ~0U;
	unsigned int dev_backlog_ns = ~0U;
	unsigned int max_preload = ~0U;
	unsigned int update_timeslot_timer_ns = ~0U;
	inet_prefix ctrl_addr;
	int has_addr = 0;

	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "flow_limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&flow_plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"flow_limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "buckets") == 0) {
			NEXT_ARG();
			if (get_unsigned(&buckets, *argv, 0)) {
				fprintf(stderr, "Illegal \"buckets\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "rate") == 0) {
			NEXT_ARG();
			if (get_rate(&data_rate, *argv)) {
				fprintf(stderr, "Illegal \"rate\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "timeslot") == 0) {
			NEXT_ARG();
			fprintf(stderr, "Deprecated \"timeslot\", use \"timeslot_mul\" and \"timeslot_shift\"\n");
			return -1;
		} else if (strcmp(*argv, "req_cost") == 0) {
			NEXT_ARG();
			if (get_unsigned(&req_cost, *argv, 0)) {
				fprintf(stderr, "Illegal \"req_cost\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "req_bucket") == 0) {
			NEXT_ARG();
			if (get_unsigned(&req_bucketlen, *argv, 0)) {
				fprintf(stderr, "Illegal \"req_bucket\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "req_gap") == 0) {
			NEXT_ARG();
			if (get_unsigned(&req_min_gap, *argv, 0)) {
				fprintf(stderr, "Illegal \"req_gap\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "ctrl") == 0) {
			NEXT_ARG();
			if (get_addr_1(&ctrl_addr, *argv, AF_INET) < 0) {
				fprintf(stderr, "Illegal \"ctrl\"\n");
				return -1;
			}
			has_addr = 1;
		} else if (strcmp(*argv, "timeslot_mul") == 0) {
			NEXT_ARG();
			if (get_unsigned(&timeslot_mul, *argv, 0)) {
				fprintf(stderr, "Illegal \"timeslot_mul\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "timeslot_shift") == 0) {
			NEXT_ARG();
			if (get_unsigned(&timeslot_shift, *argv, 0)) {
				fprintf(stderr, "Illegal \"timeslot_shift\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "miss_threshold") == 0) {
			NEXT_ARG();
			if (get_unsigned(&miss_threshold, *argv, 0)) {
				fprintf(stderr, "Illegal \"miss_threshold\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "backlog") == 0) {
			NEXT_ARG();
			if (get_unsigned(&dev_backlog_ns, *argv, 0)) {
				fprintf(stderr, "Illegal \"backlog\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "preload") == 0) {
			NEXT_ARG();
			if (get_unsigned(&max_preload, *argv, 0)) {
				fprintf(stderr, "Illegal \"preload\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "update_timer") == 0) {
			NEXT_ARG();
			if (get_unsigned(&update_timeslot_timer_ns, *argv, 0)) {
				fprintf(stderr, "Illegal \"update_timer\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	if (plimit != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_PLIMIT,
			  &plimit, sizeof(plimit));
	if (flow_plimit != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_FLOW_PLIMIT,
			  &flow_plimit, sizeof(flow_plimit));
	if (buckets) {
		unsigned int log = ilog2(buckets);
		addattr_l(n, 1024, TCA_FASTPASS_BUCKETS_LOG,
			  &log, sizeof(log));
	}
	if (data_rate != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_DATA_RATE,
				&data_rate, sizeof(data_rate));
	if (tslot_len != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_TIMESLOT_NSEC,
			  &tslot_len, sizeof(tslot_len));
	if (req_cost != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_REQUEST_COST,
			  &req_cost, sizeof(req_cost));
	if (req_bucketlen != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_REQUEST_BUCKET,
			  &req_bucketlen, sizeof(req_bucketlen));
	if (req_min_gap != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_REQUEST_GAP,
			  &req_min_gap, sizeof(req_min_gap));
	if (has_addr != 0)
		addattr_l(n, 1024, TCA_FASTPASS_CONTROLLER_IP,
			  &ctrl_addr.data[0], sizeof(__u32));
	if (timeslot_mul != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_TIMESLOT_MUL,
			  &timeslot_mul, sizeof(timeslot_mul));
	if (timeslot_shift != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_TIMESLOT_SHIFT,
			  &timeslot_shift, sizeof(timeslot_shift));
	if (miss_threshold != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_MISS_THRESHOLD,
			  &miss_threshold, sizeof(miss_threshold));
	if (dev_backlog_ns != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_DEV_BACKLOG_NS,
			  &dev_backlog_ns, sizeof(dev_backlog_ns));
	if (max_preload != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_MAX_PRELOAD,
			  &max_preload, sizeof(max_preload));
	if (update_timeslot_timer_ns != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_UPDATE_TIMESLOT_TIMER_NS,
			  &update_timeslot_timer_ns, sizeof(update_timeslot_timer_ns));

	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int fastpass_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_FASTPASS_MAX + 1];
	unsigned int plimit, flow_plimit;
	unsigned int buckets_log;
	unsigned int data_rate;
	unsigned int tslot_len;
	unsigned int req_cost;
	unsigned int req_bucketlen;
	unsigned int req_min_gap;
	struct in_addr ctrl_ip_addr;
	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_FASTPASS_MAX, opt);

	if (tb[TCA_FASTPASS_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_PLIMIT]) >= sizeof(__u32)) {
		plimit = rta_getattr_u32(tb[TCA_FASTPASS_PLIMIT]);
		fprintf(f, "limit %up ", plimit);
	}
	if (tb[TCA_FASTPASS_FLOW_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_FLOW_PLIMIT]) >= sizeof(__u32)) {
		flow_plimit = rta_getattr_u32(tb[TCA_FASTPASS_FLOW_PLIMIT]);
		fprintf(f, "flow_limit %up ", flow_plimit);
	}
	if (tb[TCA_FASTPASS_BUCKETS_LOG] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_BUCKETS_LOG]) >= sizeof(__u32)) {
		buckets_log = rta_getattr_u32(tb[TCA_FASTPASS_BUCKETS_LOG]);
		fprintf(f, "buckets %u ", 1U << buckets_log);
	}
	if (tb[TCA_FASTPASS_DATA_RATE] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_DATA_RATE]) >= sizeof(__u32)) {
		data_rate = rta_getattr_u32(tb[TCA_FASTPASS_DATA_RATE]);
		fprintf(f, "rate %s ", sprint_rate(data_rate, b1));
	}
	if (tb[TCA_FASTPASS_TIMESLOT_NSEC] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_TIMESLOT_NSEC]) >= sizeof(__u32)) {
		tslot_len = rta_getattr_u32(tb[TCA_FASTPASS_TIMESLOT_NSEC]);
		fprintf(f, "timeslot %u ", tslot_len);
	}
	if (tb[TCA_FASTPASS_REQUEST_COST] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_REQUEST_COST]) >= sizeof(__u32)) {
		req_cost = rta_getattr_u32(tb[TCA_FASTPASS_REQUEST_COST]);
		fprintf(f, "req_cost %u ", req_cost);
	}
	if (tb[TCA_FASTPASS_REQUEST_BUCKET] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_REQUEST_BUCKET]) >= sizeof(__u32)) {
		req_bucketlen = rta_getattr_u32(tb[TCA_FASTPASS_REQUEST_BUCKET]);
		fprintf(f, "req_bucket %u ", req_bucketlen);
	}
	if (tb[TCA_FASTPASS_REQUEST_GAP] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_REQUEST_GAP]) >= sizeof(__u32)) {
		req_min_gap = rta_getattr_u32(tb[TCA_FASTPASS_REQUEST_GAP]);
		fprintf(f, "req_gap %u ", req_min_gap);
	}
	if (tb[TCA_FASTPASS_CONTROLLER_IP] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_CONTROLLER_IP]) >= sizeof(__u32)) {
		ctrl_ip_addr.s_addr = rta_getattr_u32(tb[TCA_FASTPASS_CONTROLLER_IP]);
		fprintf(f, "ctrl %s ", inet_ntoa(ctrl_ip_addr));
	}
	if (tb[TCA_FASTPASS_TIMESLOT_MUL] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_TIMESLOT_MUL]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_TIMESLOT_MUL]);
		fprintf(f, "timeslot_mul %u ", param);
	}
	if (tb[TCA_FASTPASS_TIMESLOT_SHIFT] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_TIMESLOT_SHIFT]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_TIMESLOT_SHIFT]);
		fprintf(f, "timeslot_shift %u ", param);
	}
	if (tb[TCA_FASTPASS_MISS_THRESHOLD] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_MISS_THRESHOLD]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_MISS_THRESHOLD]);
		fprintf(f, "miss_threshold %u ", param);
	}
	if (tb[TCA_FASTPASS_DEV_BACKLOG_NS] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_DEV_BACKLOG_NS]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_DEV_BACKLOG_NS]);
		fprintf(f, "backlog %u ", param);
	}
	if (tb[TCA_FASTPASS_MAX_PRELOAD] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_MAX_PRELOAD]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_MAX_PRELOAD]);
		fprintf(f, "preload %u ", param);
	}
	if (tb[TCA_FASTPASS_UPDATE_TIMESLOT_TIMER_NS] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_UPDATE_TIMESLOT_TIMER_NS]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_UPDATE_TIMESLOT_TIMER_NS]);
		fprintf(f, "update_timer %u ", param);
	}

	return 0;
}

static int fastpass_print_xstats(struct qdisc_util *qu, FILE *f,
			   struct rtattr *xstats)
{
	struct tc_fastpass_qd_stats *st;
	struct fp_sched_stat *scs;
	struct fp_socket_stat *sks;
	struct fp_proto_stat *sps;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);

	if (st->version != FASTPASS_STAT_VERSION) {
		fprintf(f, "  unknown statistics version number %d, expected %d\n",
			st->version, FASTPASS_STAT_VERSION);
		return -1;
	}

	scs = (struct fp_sched_stat *)&st->sched_stats[0];
	sks = (struct fp_socket_stat *)&st->socket_stats[0];
	sps = (struct fp_proto_stat *)&st->proto_stats[0];

	/* time */
	fprintf(f, "  stat version %u ", st->version);
	fprintf(f, ", timestamp 0x%llX ", st->stat_timestamp);
	fprintf(f, ", timeslot 0x%llX", st->current_timeslot);

	/* flow statistics */
	fprintf(f, "\n  %u flows (%u inactive, %u unrequested)",
		st->flows, st->inactive_flows, st->n_unreq_flows);
	fprintf(f, ", %llu gc", scs->gc_flows);
	fprintf(f, ", next request in %llu ns", st->time_next_request);

	/* timeslot statistics */
	fprintf(f, "\n  horizon mask 0x%016llx", st->horizon_mask);
	fprintf(f, ", total %llu allocations", st->alloc_tslots);
	fprintf(f, ", %llu successful timeslots", scs->sucessful_timeslots);
	fprintf(f, " (%llu behind, %llu fast)", scs->late_enqueue, scs->early_enqueue);
	fprintf(f, ", %llu missed", scs->missed_timeslots);
	fprintf(f, ", %llu high_backlog", scs->backlog_too_high);
	fprintf(f, ", %llu assumed_lost", scs->timeslots_assumed_lost);
	fprintf(f, "  (%llu late", scs->alloc_too_late);
	fprintf(f, ", %llu premature)", scs->alloc_premature);

	/* total since reset */
	fprintf(f, "\n  since reset at 0x%llX: ", sps->last_reset_time);
	fprintf(f, " demand %llu", st->demand_tslots);
	fprintf(f, ", requested %llu", st->requested_tslots);
	fprintf(f, " (%llu yet unrequested)", st->demand_tslots - st->requested_tslots);
	fprintf(f, ", acked %llu", st->acked_tslots);
	fprintf(f, ", allocs %llu", st->alloc_tslots);
	fprintf(f, ", used %llu", st->used_tslots);

	/* egress packet statistics */
	fprintf(f, "\n  enqueued %llu ctrl", scs->ctrl_pkts);
	fprintf(f, ", %llu non_ctrl_highprio", scs->non_ctrl_highprio_pkts);
	fprintf(f, ", %llu ntp", scs->ntp_pkts);
	fprintf(f, ", %llu ptp", scs->ptp_pkts);
	fprintf(f, ", %llu arp", scs->arp_pkts);
	fprintf(f, ", %llu data", scs->data_pkts);
	fprintf(f, ", %llu flow_plimit", scs->flows_plimit);
	fprintf(f, ", %llu too big", scs->pkt_too_big);

	fprintf(f, "\n  %llu requests w/no a-req", scs->request_with_empty_flowqueue);

	/* protocol state */
	fpproto_print_stats(sps);

	/* error statistics */
	fprintf(f, "\n errors:");
	if (scs->allocation_errors)
		fprintf(f, "\n  %llu allocation errors in fp_classify", scs->allocation_errors);
	if (scs->classify_errors)
		fprintf(f, "\n  %llu packets could not be classified", scs->classify_errors);
	if (scs->flow_not_found_update)
		fprintf(f, "\n  %llu flow could not be found in update_current_tslot!",
				scs->flow_not_found_update);
	if (scs->req_alloc_errors)
		fprintf(f, "\n  %llu could not allocate pkt_desc for request", scs->req_alloc_errors);
	if (sks->skb_alloc_error)
		fprintf(f, "\n  %llu control packets failed to allocate skb",
				sks->skb_alloc_error);
	if (sks->xmit_errors)
		fprintf(f, "\n  %llu control packets had errors traversing the IP stack",
				sks->xmit_errors);
	if (sks->rx_fragmented)
		fprintf(f, "\n  %llu received a fragmented skb (no current support)",
				sks->rx_fragmented);
	if (scs->alloc_report_flow_not_found)
		fprintf(f, "\n  %llu flow not found in alloc report (causes a reset)",
				scs->alloc_report_flow_not_found);
	if (scs->alloc_report_larger_than_requested)
		fprintf(f, "\n  %llu alloc report larger than requested_timeslots (causes a reset)",
				scs->alloc_report_larger_than_requested);
	if (scs->alloc_flow_not_found)
		fprintf(f, "\n  %llu flow not found in ALLOC payload (causes reset)",
				scs->alloc_flow_not_found);

	fpproto_print_errors(sps);

	/* warnings */
	fprintf(f, "\n warnings:");
	if (scs->queued_flow_already_acked)
		fprintf(f, "\n  %llu acked flows in flowqueue (possible ack just after timeout)",
				scs->queued_flow_already_acked);
	if (scs->unwanted_alloc)
		fprintf(f, "\n  %llu timeslots allocated beyond the demand of the flow (could happen due to reset / controller timeouts)",
				scs->unwanted_alloc);
	if (scs->alloc_premature)
		fprintf(f, "\n  %llu premature allocations (something wrong with time-sync?)\n",
				scs->alloc_premature);

	fpproto_print_warnings(sps);

	fprintf(f, "\n done");
	fprintf(f, "\n");
	return 0;
}

struct qdisc_util fastpass_qdisc_util = {
	.id		= "fastpass",
	.parse_qopt	= fastpass_parse_opt,
	.print_qopt	= fastpass_print_opt,
	.print_xstats	= fastpass_print_xstats,
};
