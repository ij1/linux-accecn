/*
 *
 * The Paced Chirping start-up extension can be enabled by setting sysctl paced_chirping_enabled to 1.
 * Paced chirping is described in https://riteproject.files.wordpress.com/2018/07/misundjoakimmastersthesissubmitted180515.pdf
 *
 * Authors:
 *
 *      Joakim Misund <joakim.misund@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include "paced_chirping.h"
#include <net/paced_chirping.h>

inline int paced_chirping_active(struct paced_chirping *pc)
{
	return pc && pc->state;
}
EXPORT_SYMBOL(paced_chirping_active);

bool paced_chirping_new_chirp_check(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->chirp.packets_out < tp->chirp.packets)
		return false;

	return inet_csk(sk)->icsk_ca_ops->new_chirp(sk);
}
EXPORT_SYMBOL(paced_chirping_new_chirp_check);

/* A discontinuous link in the sens that it has idle periods
 * followed by sending at a much higher rate compared to average.
 * This kind of link cannot be handled by original chirp analysis.
 * Note that WiFi without aggregation is not discontinuous with this description. */
static bool paced_chirping_is_discontinuous_link(struct paced_chirping *pc)
{
	return (pc->aggregate_estimate>>AGGREGATION_SHIFT) > PC_DISCONT_LINK_AGGREGATION_THRESHOLD;
}

static struct cc_chirp* get_chirp_struct(struct paced_chirping *pc)
{
	return &pc->cur_chirp;
}

void paced_chirping_exit(struct sock *sk, struct paced_chirping *pc, u32 reason)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 exit_cwnd_window;
	u32 upper_limit;

	tp->is_chirping = 0;
	tp->disable_cwr_upon_ece = 0;
	tp->disable_kernel_pacing_calculation = 0;

	if (!pc || !paced_chirping_active(pc))
		return;

	pc->state = 0;

	/* TODO: Reconsider this if discontinuous link */
	if (!paced_chirping_is_discontinuous_link(pc)) {
		upper_limit = div_u64((u64)tcp_min_rtt(tp) * NSEC_PER_USEC, pc->gap_avg_ns);
		exit_cwnd_window = clamp_val(tcp_packets_in_flight(tp), 2U, upper_limit);
	} else {
		exit_cwnd_window = max(2U, tcp_packets_in_flight(tp));
	}

	switch(reason) {
	case PC_EXIT_ALLOCATION:
		/* Don't change anything, let SS take over */
		break;
	case PC_EXIT_MAX_CHIRPS_REACHED:
	case PC_EXIT_SYSTEM_LIMITATION:
		tp->snd_cwnd = exit_cwnd_window;
		/* Do not set ssthresh as SS should take over (?) */
		break;
	case PC_EXIT_LOSS:
		tp->snd_cwnd = max(2U, exit_cwnd_window>>1);
		tp->snd_ssthresh = tp->snd_cwnd;
		break;
	case PC_EXIT_ESTIMATE_CONVERGENCE:
	case PC_EXIT_OVERLOAD:
	default:
		tp->snd_cwnd = exit_cwnd_window;
		tp->snd_ssthresh = tp->snd_cwnd;
	}

	if (tp->snd_cwnd_clamp < tp->snd_cwnd) {
		tp->snd_cwnd = tp->snd_cwnd_clamp;
		tp->snd_ssthresh = tp->snd_cwnd_clamp;
	}

	LOG_PRINT((KERN_DEBUG "[PC-exit] %u-%u-%hu-%hu,"
		   "%02u,%u,%d,%u,%u,%u,%u,%u,%lld,%u,%u,%u,"  /* pc */
		   "%u,%u,%u,%u,%u,%u,%u,%llu\n",            /* tp */
		   ntohl(sk->sk_rcv_saddr),
		   ntohl(sk->sk_daddr),
		   sk->sk_num,
		   ntohs(sk->sk_dport),

		   reason,
		   pc->gap_avg_ns,
		   pc->gap_avg_ad,
		   pc->gap_avg_load_ns,
		   pc->load_window,
		   pc->aggregate_estimate>>AGGREGATION_SHIFT,
		   pc->N,
		   pc->geometry,
		   pc->qdelay_from_delta_sum_ns,
		   pc->next_chirp_number,
		   pc->state,
		   pc->send_tstamp_location,

		   tcp_min_rtt(tp),
		   tp->srtt_us>>3,
		   tp->snd_cwnd,
		   tcp_packets_in_flight(tp),
		   upper_limit,
		   tp->snd_ssthresh,
		   tp->mss_cache,
		   tp->bytes_sent));

	memset(&tp->chirp, 0, sizeof(tp->chirp));
}
EXPORT_SYMBOL(paced_chirping_exit);

/******************** Chirp creating functions ********************/
u32 paced_chirping_tso_segs(struct sock *sk, struct paced_chirping* pc, unsigned int mss_now)
{
	if (paced_chirping_enabled && paced_chirping_active(pc)) {
		return 1;
	}
	return tcp_tso_autosize(sk, mss_now,
				sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs);
}
EXPORT_SYMBOL(paced_chirping_tso_segs);

void paced_chirping_chirp_gap(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->chirp.packets > tp->chirp.packets_out) {
		struct paced_chirping_ext *ext = skb_ext_add(skb, SKB_EXT_PACED_CHIRPING);
		struct skb_shared_info* info = skb_shinfo(skb);
		struct chirp *chirp = &tp->chirp;
		u64 len_ns = chirp->gap_ns;

		if (ext == NULL) {
			/* Should exit here with PC_EXIT_ALLOCATION but pc is in ca struct */
			return;
		}

		chirp->gap_ns = max_t(s32, chirp->gap_ns - chirp->gap_step_ns, 0);
		chirp->packets_out++;
		ext->chirp_number = chirp->chirp_number;
		ext->packets = chirp->packets;
		ext->scheduled_gap = len_ns;
		info->pacing_location  = INTERNAL_PACING;
		info->pacing_tstamp = ktime_get_ns();

		if (chirp->packets_out == chirp->packets) {
			tp->tcp_wstamp_ns += chirp->guard_interval_ns;
			ext->scheduled_gap = chirp->guard_interval_ns;

			if (inet_csk(sk)->icsk_ca_ops->new_chirp)
				inet_csk(sk)->icsk_ca_ops->new_chirp(sk);
		} else {
			tp->tcp_wstamp_ns += len_ns;
		}
	}
}

static void paced_chirping_schedule_new_chirp(struct sock *sk,
					      struct paced_chirping *pc,
					      u32 N,
					      u64 gap_avg_ns,
					      u64 gap_avg_load_ns,
					      u16 geometry)
{
	struct tcp_sock *tp = tcp_sk(sk);

	u64 guard_interval_ns;
	u64 gap_step_ns;
	u64 initial_gap_ns;
	u64 average_gap_ns;

	/* A chirp consists of N packets sent with linearly decreasing inter-packet time (increasing rate).
	 *
	 * Gap between packet i-1 and i is initial_gap_ns - gap_step_ns * i, where i >= 2 (second packet)
	 *
	 * initial_gap_ns is the inter-packet time between the first and second packet
	 * It is set to the average gap in the chirp times the geometry. Geometry is in the range [1.0, 3.0]
	 *
	 * gap_step_ns is the (negative) slope of the inter-packet times
	 *                   target average gap * (geometry - 1) * 2
	 * gap_step_ns =     ----------------------------------------
	 *                                      N
	 * This calculation makes the actual average gap slightly higher than the target average gap.
	 *
	 * guard_interval_ns is the time in-between chirps needed to spread the chirps enough to keep
	 * the average packet gap to gap_avg_load_ns.
	 *
	 * guard_interval_ns = MAX( gap_avg_load_ns + (N-1) * gap_avg_load_ns - average_gap_ns, target average gap )
	 *
	 * The chirp length is the total sum of the gaps between the packets in a chirp.
	 * Denote initial gap by a, and step by s.
	 * |pkt| -------- |pkt| ------- |pkt| ------ |pkt| ----- |pkt| ----- |pkt| ...
	 *          a            (a-s)        (a-2s)       (a-3s)      (a-4s)      ...
	 *
	 * The sum is a + (a-s) + (a-2s) + ... + (a-(N-2)s)
	 *            = (N-1) * a - (1 + 2 + ... + (N-2)) * s
	 *            = (N-1) * a - s * (N-2)*(N-1)/2
	 * Average gap is then ((N-1) * a - s * (N-2)*(N-1)/2) /(N-1)
	 *            = a - s * (N-2)/2
	 */

	initial_gap_ns = (gap_avg_ns * geometry) >> PC_G_G_SHIFT;

	/* Calculate the linear decrease in inter-packet gap */
	gap_step_ns = gap_avg_ns * ((geometry - (1 << PC_G_G_SHIFT)) << 1);
	gap_step_ns = DIV64_U64_ROUND_UP(gap_step_ns, N - 1) >> PC_G_G_SHIFT;

	average_gap_ns = initial_gap_ns - ((gap_step_ns * (N - 2)) >> 1);

	/*
	 * If load gap is smaller than average probe gap, then set probe gap
	 * to the load gap. We shouldn't really be probing for less than what
	 * we are "sure" we can claim.
	 */
	if (gap_avg_load_ns > average_gap_ns)
		guard_interval_ns = gap_avg_load_ns + (N - 1) * (gap_avg_load_ns - average_gap_ns);
	else
		guard_interval_ns = gap_avg_ns;

	tp->chirp.packets = N;
	tp->chirp.gap_ns = initial_gap_ns;
	tp->chirp.gap_step_ns = gap_step_ns;
	tp->chirp.guard_interval_ns = guard_interval_ns;
	tp->chirp.packets_out = 0;
	tp->chirp.chirp_number = pc->next_chirp_number++;

	tp->snd_cwnd = tcp_packets_in_flight(tp) + (N << 1);
}

static bool enough_data_for_chirp(struct sock *sk, struct tcp_sock *tp, int N)
{
	return READ_ONCE(tp->write_seq) - tp->snd_nxt >= tp->mss_cache * N;
}
static bool paced_chirping_new_chirp_startup(struct sock *sk, struct paced_chirping *pc)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 avg_gap_of_chirp = min(pc->gap_avg_ns, pc->gap_avg_load_ns);
	u32 N = pc->N;
	u16 geometry = pc->geometry;

	if (pc->next_chirp_number <= PC_INITIAL_CHIRP_NUMBER+1)
		N = PC_FIRST_ROUND_CHIRPS_SIZE;
	else if (pc->next_chirp_number <= PC_INITIAL_CHIRP_NUMBER+3)
		N = PC_SECOND_ROUND_CHIRPS_SIZE;

	 /* Halt sending? */
	if (tcp_packets_in_flight(tp) >= pc->load_window)
		return true;
	if (!enough_data_for_chirp(sk, tp, N))
		return false; /* Just send away, TODO: Handle app limited */

	/* If there is aggregation, shift the center of the chirps downwards
	 * Really only useful if average service rate is used. */
	if (paced_chirping_is_discontinuous_link(pc)) {
		avg_gap_of_chirp = avg_gap_of_chirp - (avg_gap_of_chirp>>PC_DISCONT_LINK_CHIRP_AVG_SUB_SHIFT);
		geometry = min_t(u32, pc->geometry, 1536U);
	}
	paced_chirping_schedule_new_chirp(sk, pc, N, avg_gap_of_chirp, pc->gap_avg_load_ns, geometry);

	return false;
}

bool paced_chirping_new_chirp(struct sock *sk, struct paced_chirping *pc)
{
	if (!pc || !paced_chirping_active(pc))
		return false;
	return paced_chirping_new_chirp_startup(sk, pc);
}
EXPORT_SYMBOL(paced_chirping_new_chirp);

/* Returns the inter-arrival time between the ack that acked this packet and the ack
 * that acked the previous packet. If the same ack acked multiple packets this will
 * (currently) return 0 for the packets after the first.
 * Might be reasonable to have inter-arrival time and analysis on a per ack basis. */
static u64 get_recv_gap_ns(struct tcp_sock *tp, struct paced_chirping *pc, struct sk_buff *skb)
{
	u64 recv_gap = ULLONG_MAX;

	/* Remote time-stamp based */
	if (paced_chirping_use_remote_tsval && tp->rx_opt.saw_tstamp) {
		if (pc->prev_rcv_tsval) {
			u64 recv_gap_us = (tp->rx_opt.rcv_tsval - pc->prev_rcv_tsval) *
			                  (USEC_PER_SEC / TCP_TS_HZ);
			recv_gap = recv_gap_us * NSEC_PER_USEC;

			if (!pc->rcv_tsval_us_granul && tp->srtt_us &&
			    /* recv_gap_us > srtt(ms) * 2 */
			    (recv_gap_us > (tp->srtt_us >> (3 + 10 - 1))))
				pc->rcv_tsval_us_granul = 1;
		}
		pc->prev_rcv_tsval = tp->rx_opt.rcv_tsval;
	}

	/* Local time-stamp based */
	if (pc->prev_recv_tstamp && !pc->rcv_tsval_us_granul) {
		recv_gap = (tp->tcp_mstamp - pc->prev_recv_tstamp) * NSEC_PER_USEC;
	}
	pc->prev_recv_tstamp = tp->tcp_mstamp;

	return recv_gap;
}

static u64 get_send_gap_ns(struct paced_chirping *pc, struct sk_buff *skb)
{
	struct skb_shared_info* info = skb_shinfo(skb);
	u64 send_gap = pc->prev_send_tstamp ?
		       info->pacing_tstamp - pc->prev_send_tstamp : 0;

	pc->prev_send_tstamp = info->pacing_tstamp;
	pc->send_tstamp_location = info->pacing_location;

	return send_gap;
}

static u32 paced_chirping_get_queueing_delay_us(struct tcp_sock *tp, struct paced_chirping *pc, struct sk_buff *skb)
{
	s64 rtt_us;
	u32 queue_delay_us;
	u64 last_ackt = tcp_skb_timestamp_us(skb);

	/* Iterate over all acked pkts and choose the newest timestamp.
	 * This is necessary to deal with delayed acks. If not, chirp
	 * estimate will be way too optimistic. */
	skb_rbtree_walk_from(skb) {
		if (after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			break;
		last_ackt = tcp_skb_timestamp_us(skb);
	}

	rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, last_ackt);
	queue_delay_us = (u32)max_t(s64, 0LL, rtt_us - tcp_min_rtt(tp));

	if (paced_chirping_use_remote_tsval && pc->rcv_tsval_us_granul)
		queue_delay_us = div_u64((u64)max_t(s64, 0LL, pc->qdelay_from_delta_sum_ns), NSEC_PER_USEC);

	return queue_delay_us;
}

/* Assume in flight stays fairly constant, alright? */
static inline u32 get_per_packet_ewma_shift(struct tcp_sock *tp)
{
	/* Should be at least 16 pkts */
	return max_t(u32, 4, ilog2(tcp_packets_in_flight(tp) + 2));
}

static void update_recv_gap_estimate_ns(struct paced_chirping *pc, u32 ewma_shift, u64 recv_gap)
{
	s64 difference = (s64)(recv_gap - pc->recv_gap_estimate_ns);
	EWMA(pc->recv_gap_ad, difference, ewma_shift);
	EWMA(pc->recv_gap_estimate_ns, recv_gap, ewma_shift);
}

/* Proactive: Estimates that are based on service rate measured over (usually)
 *            a fraction of the round-trip time. Needs transient congestion. */
static u32 paced_chirping_get_proactive_service_time(struct tcp_sock *tp, struct cc_chirp *c)
{
	u64 interval = c->rate_interval_ns;
	u32 delivered = c->rate_delivered;

	if (!interval || !delivered)
		return UINT_MAX;
	do_div(interval, delivered);

	return interval;
}

/* Reactive:  Estimates that are overly conservative unless continuous utilization
 *            of the link is the case. Needs persistent congestion.
 * TODO: Data suggests this is too conservative because it does not include
 * headers. */
static u32 paced_chirping_get_reactive_service_time(struct tcp_sock *tp)
{
	u64 interval = tp->rate_interval_us * NSEC_PER_USEC;
	u32 delivered = tp->rate_delivered;

	if (!interval || !delivered)
		return UINT_MAX;
	do_div(interval, delivered);

	return interval;
}

static u32 paced_chirping_get_persistent_queueing_delay_us(struct tcp_sock *tp, struct paced_chirping *pc, struct cc_chirp *c)
{
	/* The minimum queueing delay over a chirp is a hot candidate. */
	return c->min_qdelay_us == UINT_MAX ? 0 : c->min_qdelay_us;
}

static u32 paced_chirping_get_best_persistent_service_time_estimate(struct tcp_sock *tp, struct paced_chirping *pc, struct cc_chirp *c)
{
	u32 reactive_service_time_ns = paced_chirping_get_reactive_service_time(tp);
	u32 reactive_recv_gap_estimate_ns = pc->recv_gap_estimate_ns;
	return min(reactive_service_time_ns, reactive_recv_gap_estimate_ns);
}

static bool paced_chirping_should_use_persistent_service_time(struct tcp_sock *tp, struct paced_chirping *pc, struct cc_chirp *c)
{
	u64 qdelay_us = paced_chirping_get_persistent_queueing_delay_us(tp, pc, c);
	/* (RTT + variation) * X%, X scaled by 1024 */
	u64 threshold = (u64)tcp_min_rtt(tp) * paced_chirping_service_time_queueing_delay_percent;
	do_div(threshold, 1024U);

	if (paced_chirping_is_discontinuous_link(pc))
		threshold = max(threshold, 10000ULL);

	return qdelay_us > threshold;
}

/******************** Chirp analysis function ********************/
static u32 paced_chirping_run_analysis(struct sock *sk, struct paced_chirping *pc, struct cc_chirp *c, struct sk_buff *skb)
{
	struct paced_chirping_ext *ext;
	struct tcp_sock *tp = tcp_sk(sk);

	s64 rtt_us;           /* RTT measured for this packet*/
	u32 qdelay;           /* Measured queue delay for this packet */
	u32 qdelay_diff;      /* Difference in measured queueing delay (this and start of excursion) */
	u64 send_gap;         /* Gap between this packet and the previous packet */
	u64 recv_gap;         /* Gap between this packet/ack and the previous packet/ack */
	u64 scheduled_gap;    /* The gap scheduled between this packet and the next. */
	u32 packets_in_chirp; /* The number of packets in the current chirp */
	u32 ewma_shift;       /* shift value to use for per packet EWMA */
	u32 proactive = UINT_MAX;

	ext = skb_ext_find(skb, SKB_EXT_PACED_CHIRPING);
	rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, tcp_skb_timestamp_us(skb));

	if (rtt_us <= 0 || !ext)
		return 0;

	scheduled_gap = ext->scheduled_gap;
	packets_in_chirp = ext->packets;
	send_gap = get_send_gap_ns(pc, skb);
	recv_gap = get_recv_gap_ns(tp, pc, skb);
	qdelay = paced_chirping_get_queueing_delay_us(tp, pc, skb);
	ewma_shift = get_per_packet_ewma_shift(tp);

	c->min_qdelay_us = min(c->min_qdelay_us, qdelay);

	c->packets_acked++;

	if (recv_gap != ULLONG_MAX) {
		/* Detecting discontinuous links
		 * TODO: Deal with delayed acks and ack thinning. */
		if (//recv_gap != 0 &&
			recv_gap < (pc->gap_avg_ns>>1)) {
			c->aggregated++;
		}
		if (recv_gap > send_gap &&
		    recv_gap > (pc->gap_avg_ns<<1) &&
		    c->packets_acked != 1U) { /* Ignore guard interval. */
			c->jumps++;
		}

		if (!(recv_gap > (pc->gap_avg_ns<<1)) ||
		    (pc->prev_qdelay * NSEC_PER_USEC > send_gap &&
		     c->rate_delivered < tcp_packets_in_flight(tp))) { /* If not jump, collect */
			c->rate_interval_ns += recv_gap;
			c->rate_delivered += 1;
		} else { /* If jump, use estimate */

			if (pc->start_qdelay > pc->prev_qdelay)
				c->rate_interval_ns += (pc->start_qdelay - pc->prev_qdelay) * NSEC_PER_USEC;

			proactive = paced_chirping_get_proactive_service_time(tp, c);

			c->rate_interval_ns = 0;
			c->rate_delivered = 0;
			pc->start_qdelay = qdelay;

			if (proactive != UINT_MAX) {
				pc->proactive_service_time_ns = proactive;
				c->rate_interval_ns += (proactive<<3);
				c->rate_delivered += (1<<3);
			}

		}
		pc->prev_qdelay = qdelay;

		/* TODO: This might be superfluous */
		update_recv_gap_estimate_ns(pc, ewma_shift, recv_gap);

		EWMA(pc->queueing_delay_mad_us, abs((s32)(qdelay - pc->queueing_delay_average_us)), ewma_shift);
		EWMA(pc->queueing_delay_average_us, qdelay, ewma_shift);

		/* TODO: reset sum if rtt is close to min_rtt and sum close to 0 */
		pc->qdelay_from_delta_sum_ns = pc->qdelay_from_delta_sum_ns + recv_gap - send_gap;
	}

	TRACE_PRINT((KERN_DEBUG "[PC-analysis] %u-%u-%hu-%hu,"
		     "%08u,%08u,%08llu,%08llu,%08llu,%08u,"
		     "%08u,%02u,%llu,%u,%llu,%u\n",
		     ntohl(sk->sk_rcv_saddr),
		     ntohl(sk->sk_daddr),
		     sk->sk_num,
		     ntohs(sk->sk_dport),

		     c->chirp_number,
		     packets_in_chirp,
		     scheduled_gap,
		     send_gap,
		     recv_gap,
		     qdelay,

		     c->min_qdelay_us,
		     pc->send_tstamp_location,
		     tp->tcp_mstamp,
		     proactive,
		     c->rate_interval_ns,
		     c->rate_delivered));

	/* Start of original online analysis */
	if (c->packets_acked == 1U) {
		c->last_delay = qdelay;
		return 0;
	}

	if (c->valid) { /* All other packets */
		/* TODO: Scheduled gap is gap between this packet and the next packet, so it shouldn't
		 *       (really) be compared with send gap, which is between the previous packet and
		 *       this packet. This is probably why the code before stored send gap in chirp,
		 *       because it was using the scheduled one, and not timestamps.
		 *       Old comment: Previously stored scheduled gap in cc_chirp, but are using timestamps now.
		 *
		 *       Rectify by storing previous scheduled gap. Also reconsider whether this is
		 *       necessary or if it should be more tolerant.
		 */
		if (c->packets_acked < packets_in_chirp &&
		    (send_gap<<1) < scheduled_gap) {
			c->valid = 1;
		}

		c->uncounted++;

		if (!c->in_excursion &&
		    c->last_delay < qdelay &&
		    c->packets_acked < packets_in_chirp) {
			c->excursion_start = c->last_delay;
			c->excursion_len = 0;
			c->last_sample = send_gap;
			c->max_q = 0;
			c->in_excursion = 1;
		}

		if (c->in_excursion) {

			qdelay_diff = max(c->last_delay, c->excursion_start) - c->excursion_start;

			if (qdelay_diff >= ((c->max_q>>1) + (c->max_q>>3))) {
				/* FIXME: is it ok to have a too small type for max_q? */
				c->max_q = min_t(u16, max_t(u32, c->max_q, qdelay_diff), 0xFFFFU);
				c->excursion_len++;

				if (c->packets_acked != packets_in_chirp &&
				    c->last_delay < qdelay) {
					c->gap_pending += send_gap;
					c->pending_count++;
				}
			} else {
				if (c->excursion_len >= paced_chirping_L) {
					c->gap_total += c->gap_pending;
					c->uncounted -= c->pending_count;
				}
				c->gap_pending = 0;
				c->pending_count = 0;
				c->in_excursion = 0;
				c->excursion_index = c->packets_acked;

				if (!c->in_excursion &&
				    c->last_delay < qdelay &&
				    c->packets_acked < packets_in_chirp) {
					c->excursion_start = c->last_delay;
					c->excursion_len = 1;
					c->last_sample = send_gap;
					c->max_q = 0;
					c->in_excursion = 1;
					c->gap_pending = send_gap;
					c->pending_count = 1;
				}
			}
		} else {
			c->excursion_index = c->packets_acked;
		}

		if (c->packets_acked != packets_in_chirp) {
			c->last_delay = qdelay;
		}
	}

	/* TODO: Add print statement from logging */

	if (c->packets_acked == packets_in_chirp) {
		if (!c->in_excursion)
			c->last_sample = send_gap;

		c->gap_total += c->uncounted * c->last_sample;

		if (c->gap_total != 0 &&
		    c->valid &&
		    packets_in_chirp >= 2U) {
			return div_u64(c->gap_total, packets_in_chirp - 1);
		}
		return UINT_MAX;
	}
	return 0;
}

/******************** Controller/Algorithm functions ********************/
static u32 paced_chirping_get_smoothed_queueing_delay_us(struct tcp_sock *tp, struct paced_chirping *pc)
{
	/* The minimum queueing delay over a chirp is a hot candidate. */
	return tp->srtt_us ? (tp->srtt_us>>3) - tcp_min_rtt(tp) : 0;
}

static bool paced_chirping_should_exit_overload(struct tcp_sock *tp, struct paced_chirping *pc, struct cc_chirp *c)
{
	u32 qdelay_us = paced_chirping_get_smoothed_queueing_delay_us(tp, pc);

	return qdelay_us >= paced_chirping_overload_exit_queueing_delay_thresh_us;
}

static void update_gap_estimate(struct paced_chirping *pc, struct cc_chirp *c, u32 ewma_shift, u32 estimate)
{
	s32 difference = (s32)estimate - (s32)pc->gap_avg_ns;

	EWMA(pc->gap_avg_ad, difference, ewma_shift);
	EWMA(pc->gap_avg_ns, estimate, ewma_shift);
}

static void update_gap_load_estimate(struct paced_chirping *pc, struct cc_chirp *c, u32 ewma_shift, u32 estimate)
{
	if (estimate < pc->gap_avg_load_ns)
		EWMA(pc->gap_avg_load_ns, estimate, ewma_shift);
}

static void update_aggregation_estimate(struct paced_chirping *pc, struct cc_chirp *c, u32 ewma_shift)
{
	u64 agg = 1;

	if (c->jumps && c->aggregated)
		agg = (c->aggregated + c->jumps) / c->jumps;

	EWMA(pc->aggregate_estimate, agg << AGGREGATION_SHIFT, ewma_shift);
}

static void update_chirp_size(struct paced_chirping *pc, struct cc_chirp *c)
{
	/* Try to have a chirp cover 4 aggregates. */
	u32 cover_aggregates = (pc->aggregate_estimate<<PC_CHIRP_SIZE_COVER_AGGREGATION_SHIFT)>>AGGREGATION_SHIFT;

	/* TODO: Make sure 1 or 2 chirps of this size can fit in one RTT. */
	pc->N = clamp_val(cover_aggregates, PC_CHIRP_SIZE_MIN, PC_CHIRP_SIZE_MAX);
}

static void update_chirp_geometry(struct paced_chirping *pc, struct cc_chirp *c)
{
	u32 low_thresh;
	u32 rel_diff;

	/* As the load gap approaches the average gap the geometry of the chirps should decrease.
	 * This increases the likelihood that cross-traffic is able to affect the estimate.
	 *
	 * The lower limit aims at keeping at least 2 us difference between each gap.
	 * The value of 2 is arbitrary. step = (avg * 2 * (geom - 1)) / (N-1). step >= 2000 ->
	 */
	low_thresh = 1U << PC_G_G_SHIFT;
	low_thresh += div_u64((u64)(pc->N-1)<<(10 + PC_G_G_SHIFT), pc->gap_avg_ns+1);

	rel_diff = div_u64((u64)pc->gap_avg_load_ns<<PC_G_G_SHIFT, pc->gap_avg_ns+1);

	pc->geometry = clamp_val(rel_diff, low_thresh, 2U << PC_G_G_SHIFT);
}

static inline void update_load_window(struct tcp_sock *tp, struct paced_chirping *pc)
{
	u64 window = ((u64)tp->srtt_us * NSEC_PER_USEC) >> 3;
	do_div(window, max(1U, pc->gap_avg_load_ns));
	pc->load_window = min_t(u32, window, tp->snd_cwnd_clamp);
}

static u32 get_per_chirp_ewma_shift(struct tcp_sock *tp, u32 chirp_size)
{
	/* EWMA shift depends on fraction of packets over RTT in this chirp. */
	s32 shift = (s32)ilog2(tcp_packets_in_flight(tp) + 1) - (s32)ilog2(chirp_size);
	return max(1, shift); /* Should be at least 2 chirps */
}

static void paced_chirping_reset_chirp(struct cc_chirp *c)
{
	c->gap_total = 0;
	c->gap_pending = 0;
	c->chirp_number = 0;
	c->packets_acked = 0;
	c->excursion_index = 0;
	c->uncounted = 0;
	c->in_excursion = 0;
	c->valid = 1;
	c->excursion_len = 0;
	c->ack_cnt = 0;
	c->pending_count = 0;
	c->excursion_start = 0;
	c->max_q = 0;
	c->jumps = 0;
	c->aggregated = 0;

	//c->rate_interval_ns = 0;
	//c->rate_delivered = 0;

	c->min_qdelay_us = UINT_MAX;
}

static void paced_chirping_pkt_acked_startup(struct sock *sk, struct paced_chirping *pc, struct sk_buff *skb)
{
	struct paced_chirping_ext *ext;
	struct tcp_sock *tp = tcp_sk(sk);
	struct cc_chirp *c;
	u32 ewma_shift;
	u32 estimate;
	u32 proactive_service_time;
	u32 persistent_service_time;

	ext = skb_ext_find(skb, SKB_EXT_PACED_CHIRPING);
	if (!ext)
		return;

	c = get_chirp_struct(pc);
	if (c->chirp_number != ext->chirp_number) {
		paced_chirping_reset_chirp(c);
		c->chirp_number = ext->chirp_number;
	}

	/* For debugging/non-convergence safety purposes */
	if (c->chirp_number >= paced_chirping_maximum_num_chirps)
		paced_chirping_exit(sk, pc, PC_EXIT_MAX_CHIRPS_REACHED);

	if (paced_chirping_should_exit_overload(tp, pc, c))
		paced_chirping_exit(sk, pc, PC_EXIT_OVERLOAD);

	estimate = paced_chirping_run_analysis(sk, pc, c, skb);
	if (estimate) {
		ewma_shift = get_per_chirp_ewma_shift(tp, c->packets_acked + 1);

		/* TODO: I guess here is where discontinuous links are
		 * allowed to have more latency... Measure variation in
		 * queue delay. Add to pc struct..
		 * It makes sense to move faster if there is "proven" overload over time.
		 * If gap_avg is to be used to drain and set initial alpha, it makes sense
		 * to move fast here before termination. */
		persistent_service_time = paced_chirping_get_best_persistent_service_time_estimate(tp, pc, c);
		if (paced_chirping_should_use_persistent_service_time(tp, pc, c)) {
			estimate = persistent_service_time;
			ewma_shift = 1;
		}

		/* TODO: Think about this..
		 * It might be better to use gap_avg_ns/2 in case all estimates
		 * are invalid or false. no information -> slow start  */
		if (estimate == UINT_MAX || estimate > 100000000U)
			estimate = pc->gap_avg_ns;

		/* TODO: Does it make sens to try to avoid overshoot if the link
		 *       itself is making it difficult to estimate?
		 *       I think no, so all this thought of using proactive might be
		 *       not worth the complexity. It can however be used to fine tune
		 *       or improve the estimate from the chirp estimate.
		 *       In that case it should only be used on packets in an excursion.
		 * TODO: Maybe the weight should depend on how many packets are in the
		 *       excursion. If the estimate is overly optimistic
		 */
		proactive_service_time = pc->proactive_service_time_ns;
		if (paced_chirping_use_proactive_service_time &&
		    paced_chirping_is_discontinuous_link(pc) &&
		    proactive_service_time != UINT_MAX)
			estimate = min(proactive_service_time, persistent_service_time);

		update_gap_estimate(pc, c, ewma_shift, estimate);
		update_gap_load_estimate(pc, c, ewma_shift+1, pc->gap_avg_ns);
		update_aggregation_estimate(pc, c, ewma_shift);
		update_chirp_size(pc, c);
		update_chirp_geometry(pc, c);
		update_load_window(tp, pc);

		/* Exit if the load has 'catched up' with the average
		 * Previously trend had to be increasing, but I believe
		 * that forced overshoot by underestimation followed by increasing
		 * trend. */
		if (pc->gap_avg_load_ns <= pc->gap_avg_ns)
			paced_chirping_exit(sk, pc, PC_EXIT_ESTIMATE_CONVERGENCE);

		if ((!pc->send_tstamp_location || pc->send_tstamp_location == INTERNAL_PACING)
		    && pc->gap_avg_load_ns < paced_chirping_lowest_internal_pacing_gap) {
			paced_chirping_exit(sk, pc, PC_EXIT_SYSTEM_LIMITATION);
		} else if (pc->send_tstamp_location == FQ_PACING &&
			   pc->gap_avg_load_ns < paced_chirping_lowest_FQ_pacing_gap) {
			paced_chirping_exit(sk, pc, PC_EXIT_SYSTEM_LIMITATION);
		}

		/* TODO: KERN_DEBUG is not needed here */
		TRACE_PRINT((KERN_DEBUG "[PC-estimate] %u-%u-%hu-%hu,"
			     "%08u,%08u,%08u,%02u,%03u,%02u,%u,%u,%02u,%08llu,"    /* Other variables */
			     "%08u,%08d,%08u,%02u,%02u,%02u,%05u,%08lld,%06u,%02u,%02u,"  /* pc */
			     "%08u,%08u,%08u,%04u,%04u,%04u,%05u\n",                /* tp */
			     ntohl(sk->sk_rcv_saddr),
			     ntohl(sk->sk_daddr),
			     sk->sk_num,
			     ntohs(sk->sk_dport),

			     estimate,
			     proactive_service_time,
			     persistent_service_time,
			     ewma_shift,
			     c->chirp_number,
			     c->packets_acked,
			     c->valid,
			     c->ack_cnt,
			     c->rate_delivered,
			     c->rate_interval_ns,

			     pc->gap_avg_ns,
			     pc->gap_avg_ad,
			     pc->gap_avg_load_ns,
			     pc->load_window,
			     pc->aggregate_estimate>>AGGREGATION_SHIFT,
			     pc->N,
			     pc->geometry,
			     pc->qdelay_from_delta_sum_ns,
			     pc->next_chirp_number,
			     pc->state,
			     pc->send_tstamp_location,

			     tcp_min_rtt(tp),
			     c->min_qdelay_us,
			     tp->srtt_us>>3,
			     tp->snd_cwnd,
			     tcp_packets_in_flight(tp),
			     tp->snd_ssthresh,

			     tp->mss_cache));
	}
}

/* Same rtt for delayed acks in original, how to do it here? */
/* How do you preserve ack-count?  Maybe we can use the update callback */
void paced_chirping_pkt_acked(struct sock *sk, struct paced_chirping *pc, struct sk_buff *skb)
{
	/* skb should never be NULL. No need to analyze if PC is inactive*/
	/* TODO: Check that pc is not NULL. Do so in all functions. */
	if (!pc || !skb || !paced_chirping_active(pc))
		return;

	paced_chirping_pkt_acked_startup(sk, pc, skb);
}
EXPORT_SYMBOL(paced_chirping_pkt_acked);

/* This function is called only once per acknowledgement */
void paced_chirping_update(struct sock *sk, struct paced_chirping *pc, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cc_chirp *c;

	if (!pc || !paced_chirping_active(pc))
		return;

	c = get_chirp_struct(pc);
	if (c)
		c->ack_cnt++;

	/* Update when all packets have been taken of rtx queue */
	pc->old_snd_una = tp->snd_una;
}
EXPORT_SYMBOL(paced_chirping_update);

static inline void paced_chirping_set_initial_gap_avg(struct sock *sk, struct tcp_sock *tp, struct paced_chirping *pc)
{
	struct paced_chirping_cache cache;

	if (paced_chirping_use_initial_srrt && tp->srtt_us>>3) {
		u64 srtt_ns = (u64)tp->srtt_us * NSEC_PER_USEC;
		pc->gap_avg_ns = srtt_ns >> (3 + paced_chirping_gap_pkts_shift);
		pc->gap_avg_load_ns = srtt_ns >> (3 + paced_chirping_load_gap_pkts_shift);
	} else {
		pc->gap_avg_ns = paced_chirping_initial_gap_ns;
		pc->gap_avg_load_ns = paced_chirping_initial_load_gap_ns;
	}

	if (paced_chirping_use_cached_information) {
		paced_chirping_cache_get(sk, &cache);
		if (cache.srtt && cache.cwnd && cache.cwnd > TCP_INIT_CWND) {
			pc->gap_avg_ns = div_u64((u64)cache.srtt, cache.cwnd);
		}
	}

	pc->gap_avg_ns = min(pc->gap_avg_ns, paced_chirping_maximum_initial_gap);
}

static void paced_chirping_init_both(struct sock *sk, struct tcp_sock *tp,
				     struct paced_chirping *pc)
{
	/* Alter kernel behaviour*/
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	sk->sk_pacing_rate = ~0U;
	sk->sk_gso_max_segs = 1;

	tp->disable_kernel_pacing_calculation = 1;
	tp->disable_cwr_upon_ece = 1;
	tp->is_chirping = 1;

	/* Initial algorithm variables */
	pc->geometry = clamp_val(paced_chirping_initial_geometry, 1U << PC_G_G_SHIFT, 2U << PC_G_G_SHIFT);
	pc->next_chirp_number = PC_INITIAL_CHIRP_NUMBER;
	pc->N = max(paced_chirping_prob_size, 2U);
	paced_chirping_reset_chirp(get_chirp_struct(pc));
}

struct paced_chirping* paced_chirping_init(struct sock *sk, struct paced_chirping *pc)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* If caller does not have memory available try to allocate it. */
	if (!pc) {
		pc = kzalloc(sizeof(struct paced_chirping), GFP_NOWAIT | __GFP_NOWARN);
		if (!pc) {
			paced_chirping_exit(sk, pc, PC_EXIT_ALLOCATION);
			return NULL;
		}
		pc->allocated_on_heap = 1;
	} else {
		pc->allocated_on_heap = 0;
	}

	/* TODO: If set up in congestion avoidance maybe memset everything to 0.
	 *        Certainly safer than setting members explicitly. */

	paced_chirping_init_both(sk, tp, pc);
	paced_chirping_set_initial_gap_avg(sk, tp, pc);

	pc->old_snd_una = tp->snd_una;
	pc->load_window = TCP_INIT_CWND;
	pc->recv_gap_estimate_ns = pc->gap_avg_load_ns;
	pc->proactive_service_time_ns = pc->gap_avg_ns;
	pc->state = PC_STATE_ACTIVE;
	pc->prev_recv_tstamp = 0;
	pc->prev_rcv_tsval = 0;

	pc->aggregate_estimate = 1<<AGGREGATION_SHIFT;

	LOG_PRINT((KERN_DEBUG "[PC-init] %u-%u-%hu-%hu,"
		   "%u,%u,%u,%u,%u,%u,"  /* Variables */
		   "%u,%u,%u,%u,%u,%u,%u\n", /* Parameters */
		   ntohl(sk->sk_rcv_saddr),
		   ntohl(sk->sk_daddr),
		   sk->sk_num,
		   ntohs(sk->sk_dport),

		   pc->gap_avg_ns,
		   pc->gap_avg_load_ns,
		   pc->state,
		   pc->allocated_on_heap,
		   tcp_min_rtt(tp),
		   tp->srtt_us>>3,

		   paced_chirping_initial_geometry,
		   paced_chirping_L,
		   paced_chirping_maximum_initial_gap,
		   paced_chirping_maximum_num_chirps,
		   paced_chirping_prob_size,
		   paced_chirping_use_remote_tsval,
		   paced_chirping_use_cached_information));

	return pc;
}
EXPORT_SYMBOL(paced_chirping_init);

void paced_chirping_release(struct sock *sk, struct paced_chirping* pc)
{
	struct tcp_sock *tp = tcp_sk(sk);
	memset(&tp->chirp, 0, sizeof(tp->chirp));

	if (pc && pc->allocated_on_heap)
		kfree(pc);
}
EXPORT_SYMBOL(paced_chirping_release);

