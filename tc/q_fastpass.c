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

#include "protocol/fpproto.h"
#include "protocol/stat_print.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... fastpass [ limit PACKETS ]\n");
	fprintf(stderr, "              [ buckets NUMBER ] [ rate RATE ]\n");
	fprintf(stderr, "              [ timeslot_mul NUM  ] [ timeslot_shift NUM ]\n");
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
	unsigned int buckets = 0;
	unsigned int data_rate = ~0U;
	unsigned int timeslot_mul = ~0U;
	unsigned int timeslot_shift = ~0U;

	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
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
		} else if (strcmp(*argv, "flow_limit") == 0) {
			NEXT_ARG();
			fprintf(stderr, "Deprecated \"flow_limit\".\n");
			return -1;
		} else if (strcmp(*argv, "timeslot") == 0) {
			NEXT_ARG();
			fprintf(stderr, "Deprecated \"timeslot\", use \"timeslot_mul\" and \"timeslot_shift\"\n");
			return -1;
		} else if (strcmp(*argv, "req_cost") == 0) {
			NEXT_ARG();
			fprintf(stderr, "\"req_cost\" is now passed as a kernel module parameter\n");
			return -1;
		} else if (strcmp(*argv, "req_bucket") == 0) {
			NEXT_ARG();
			fprintf(stderr, "\"req_bucket\" is now passed as a kernel module parameter \"req_bucketlen\"\n");
			return -1;
		} else if (strcmp(*argv, "req_gap") == 0) {
			NEXT_ARG();
			fprintf(stderr, "\"req_gap\" is now passed as a kernel module parameter \"req_min_gap\"\n");
			return -1;
		} else if (strcmp(*argv, "ctrl") == 0) {
			NEXT_ARG();
			fprintf(stderr, "\"ctrl\" is now passed as a kernel module parameter \"ctrl_addr\"\n");
			return -1;
		} else if (strcmp(*argv, "miss_threshold") == 0) {
			NEXT_ARG();
			fprintf(stderr, "\"miss_threshold\" is now passed as a kernel module parameter\n");
			return -1;
		} else if (strcmp(*argv, "backlog") == 0) {
			NEXT_ARG();
			fprintf(stderr, "Deprecated parameter \"backlog\"\n");
			return -1;
		} else if (strcmp(*argv, "preload") == 0) {
			NEXT_ARG();
			fprintf(stderr, "\"preload\" is now passed as a kernel module parameter \"max_preload\"\n");
			return -1;
		} else if (strcmp(*argv, "update_timer") == 0) {
			NEXT_ARG();
			fprintf(stderr, "\"update_timer\" is now passed as a kernel module parameter \"update_timer_ns\"\n");
			return -1;
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
	if (buckets) {
		unsigned int log = ilog2(buckets);
		addattr_l(n, 1024, TCA_FASTPASS_BUCKETS_LOG,
			  &log, sizeof(log));
	}
	if (data_rate != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_DATA_RATE,
				&data_rate, sizeof(data_rate));
	if (timeslot_mul != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_TIMESLOT_MUL,
			  &timeslot_mul, sizeof(timeslot_mul));
	if (timeslot_shift != ~0U)
		addattr_l(n, 1024, TCA_FASTPASS_TIMESLOT_SHIFT,
			  &timeslot_shift, sizeof(timeslot_shift));

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
		fprintf(f, "flow_limit %up ", flow_plimit); /* note: deprecated */
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
		fprintf(f, "req_cost %u ", req_cost); /* note: deprecated */
	}
	if (tb[TCA_FASTPASS_REQUEST_BUCKET] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_REQUEST_BUCKET]) >= sizeof(__u32)) {
		req_bucketlen = rta_getattr_u32(tb[TCA_FASTPASS_REQUEST_BUCKET]);
		fprintf(f, "req_bucket %u ", req_bucketlen); /* note: deprecated */
	}
	if (tb[TCA_FASTPASS_REQUEST_GAP] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_REQUEST_GAP]) >= sizeof(__u32)) {
		req_min_gap = rta_getattr_u32(tb[TCA_FASTPASS_REQUEST_GAP]);
		fprintf(f, "req_gap %u ", req_min_gap); /* note: deprecated */
	}
	if (tb[TCA_FASTPASS_CONTROLLER_IP] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_CONTROLLER_IP]) >= sizeof(__u32)) {
		ctrl_ip_addr.s_addr = rta_getattr_u32(tb[TCA_FASTPASS_CONTROLLER_IP]);
		fprintf(f, "ctrl %s ", inet_ntoa(ctrl_ip_addr)); /* note: deprecated */
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
		fprintf(f, "miss_threshold %u ", param); /* note: deprecated */
	}
	if (tb[TCA_FASTPASS_DEV_BACKLOG_NS] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_DEV_BACKLOG_NS]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_DEV_BACKLOG_NS]);
		fprintf(f, "backlog %u ", param); /* note: deprecated */
	}
	if (tb[TCA_FASTPASS_MAX_PRELOAD] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_MAX_PRELOAD]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_MAX_PRELOAD]);
		fprintf(f, "preload %u ", param); /* note: deprecated */
	}
	if (tb[TCA_FASTPASS_UPDATE_TIMESLOT_TIMER_NS] &&
	    RTA_PAYLOAD(tb[TCA_FASTPASS_UPDATE_TIMESLOT_TIMER_NS]) >= sizeof(__u32)) {
		__u32 param = rta_getattr_u32(tb[TCA_FASTPASS_UPDATE_TIMESLOT_TIMER_NS]);
		fprintf(f, "update_timer %u ", param); /* note: deprecated */
	}

	return 0;
}

static int fastpass_print_xstats(struct qdisc_util *qu, FILE *f,
			   struct rtattr *xstats)
{
	fprintf(f, "please use /proc/tsq/* and /proc/fastpass/* for statistics\n");
	return 0;
}

struct qdisc_util fastpass_qdisc_util = {
	.id		= "fastpass",
	.parse_qopt	= fastpass_parse_opt,
	.print_qopt	= fastpass_print_opt,
	.print_xstats	= fastpass_print_xstats,
};
