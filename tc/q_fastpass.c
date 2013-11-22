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

static void explain(void)
{
	fprintf(stderr, "Usage: ... fastpass [ limit PACKETS ] [ flow_limit PACKETS ]\n");
	fprintf(stderr, "              [ buckets NUMBER ] [ rate RATE ]\n");
	fprintf(stderr, "              [ timeslot NSECS  ] [ req_cost NSEC ]\n");
	fprintf(stderr, "              [ req_bucket NSEC ] [ req_gap NSEC ]\n");
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
			if (get_unsigned(&tslot_len, *argv, 0)) {
				fprintf(stderr, "Illegal \"timeslot\"\n");
				return -1;
			}
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

	return 0;
}

static int fastpass_print_xstats(struct qdisc_util *qu, FILE *f,
			   struct rtattr *xstats)
{
	struct tc_fastpass_qd_stats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);

	/* flow statistics */
	fprintf(f, "  %u flows (%u inactive, %u unrequested)",
		st->flows, st->inactive_flows, st->unrequested_flows);
	fprintf(f, ", %llu gc", st->gc_flows);

	/* timeslot statistics */
	fprintf(f, "\n  at timeslot %llu", st->current_timeslot);
	fprintf(f, ", mask %llx", st->horizon_mask);
	fprintf(f, ", %llu successful", st->used_timeslots);
	fprintf(f, ", %llu missed", st->missed_timeslots);
	fprintf(f, ", %u unrequested", st->unrequested_tslots);

	/* packet statistics */
	fprintf(f, "\n  %llu highprio", st->highprio_packets);
	if (st->flows_plimit)
		fprintf(f, ", %llu flows_plimit", st->flows_plimit);
	fprintf(f, ", %llu requests", st->requests);
	if (st->time_next_request > 0)
		fprintf(f, ", next request %llu ns", st->time_next_request);

	/* other error statistics */
	if (st->allocation_errors)
		fprintf(f, "\n  %llu alloc errors\n", st->allocation_errors);

	return 0;
}

struct qdisc_util fastpass_qdisc_util = {
	.id		= "fastpass",
	.parse_qopt	= fastpass_parse_opt,
	.print_qopt	= fastpass_print_opt,
	.print_xstats	= fastpass_print_xstats,
};
