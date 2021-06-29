#ifndef _TCP_PACED_CHIRPING_H
#define _TCP_PACED_CHIRPING_H

#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/module.h>

#define LOG_PRINT(x) do { if (paced_chirping_log) printk x; if (paced_chirping_trace) trace_printk x;} while (0)
#define TRACE_PRINT(x) do { if (paced_chirping_trace) trace_printk x;} while (0)

#define EWMA(average, estimate, shift) average = average - (average>>(shift)) + (estimate>>(shift))

/* State values */
#define PC_STATE_ACTIVE                        0x01
#define PC_STATE_CONGESTION_AVOIDANCE_CONTEXT  0x02 /* TODO */

/* Used for logging/debugging */
#define PC_EXIT_SYSTEM_LIMITATION              0x00 /* If system cannot handle e.g. pacing precision */
#define PC_EXIT_LOSS                           0x01 /* A loss has happened */
#define PC_EXIT_ESTIMATE_CONVERGENCE           0x02 /* PC is finished */
#define PC_EXIT_OVERLOAD                       0x03 /* Queueing delay is unacceptable*/
#define PC_EXIT_ALLOCATION                     0x04 /* Requested allocation failed */
#define PC_EXIT_MAX_CHIRPS_REACHED             0x05 /* In case of non-convergence */

/* Shifts used to store upscaled values */
#define PC_G_G_SHIFT                            10U /* Gain and geometry shift */
#define AGGREGATION_SHIFT                        6U /* Aggregation estimate shift */

/* Constants used in the algorithm */
#define PC_INITIAL_CHIRP_NUMBER                  1U /* Used in initialization and when scheduling chirps */
#define PC_FIRST_ROUND_CHIRPS_SIZE               5U /* Number of packets in two first chirps */
#define PC_SECOND_ROUND_CHIRPS_SIZE              8U /* Number of packets in third and fourth chirp */
#define PC_CHIRP_SIZE_MIN                       16U /* Minimum number of packets in a chirp */
#define PC_CHIRP_SIZE_MAX                       64U /* Maximum number of packets in a chirp */
/* Dealing with discontinuous links */
#define PC_CHIRP_SIZE_COVER_AGGREGATION_SHIFT    2U /* Chirp size set to aggregate estimate times 2^X */
#define PC_DISCONT_LINK_AGGREGATION_THRESHOLD    2U /* Deemed discontinuous if aggregate estimate is greater */
#define PC_DISCONT_LINK_CHIRP_AVG_SUB_SHIFT      2U /* Set chirp avg to est - est/2^X */

struct cc_chirp {
	/* State variables for online calculation */
	u64     gap_total;
	u64     gap_pending;

	u32     chirp_number : 16, /* Chirp number, first chirp has number 0 */
		packets_acked :  8; /* Used to record the measured queue delays */

	u32     uncounted     : 6,
		in_excursion  : 1,
		valid         : 1,
		excursion_len : 8,
		ack_cnt       : 8,
		pending_count : 8;

	u32     excursion_start;      /* Need to be this big */
	u32     max_q;
	u32     last_delay;
	u32     last_sample;

	/* Detecting persistent queueing delay */
	u32     min_qdelay_us;

	/* Same interpretation as tp members, but
	 * only over part of a chirp with persistent queueing delay. */
	u64     rate_interval_ns;
	u8      rate_delivered;

	/* Heuristic for estimating aggregation */
	u8      jumps;
	u8      aggregated;
};

struct paced_chirping {
	/* Local timestamps */
	u64     prev_send_tstamp;	/* Send timestamp of latest handled packet */
	u8      send_tstamp_location;	/* Where in the stack the last packet was paced */
	u64     prev_recv_tstamp;	/* Recv timestamp of latest handled packet */

	/* Remote timestamp */
	u64     prev_rcv_tsval;		/* Receiver side timestamp of latest ACK */
	u8      rcv_tsval_us_granul;	/* Whether or not heuristic deems ts microsecond */

	/* Estimates */
	u32     gap_avg_ns;		/* Average gap */
	s32     gap_avg_ad;		/* Trend of average gap */

	u64     recv_gap_estimate_ns;	/* EWMA over recv gaps */
	s64     recv_gap_ad;		/* Trend of recv_gap_estimate_ns */

	u32     queueing_delay_average_us;
	u32     queueing_delay_mad_us;

	/* For discontinuous links */
	u64     proactive_service_time_ns;
	s64     proactive_service_time_ad;

	u32     prev_qdelay;
	u32     start_qdelay;

	/* Keeping load */
	u32     gap_avg_load_ns; /* Gap used to enforce a certain average load */
	u32     load_window;     /* In case RTT suddenly increases. RTT/avg_load */

	/* Alternative queueing delay calculation */
	s64     qdelay_from_delta_sum_ns; /* Sum of deltas between recv gap and send gap. */

	/* Discontinuous links */
	u32     aggregate_estimate; /* EWMA of aggregated packets / jumps */

	/* */
	u16     next_chirp_number; /* Should never wrap */
	u16     state        : 8,  /* Algorithm state */
		N            : 8;  /* Number of packets in scheduled chirps */
	u16     geometry     : 16; /* Geometry of scheduled chirps */
	u8      allocated_on_heap; /* Set if init-function allocated this structure */
	struct cc_chirp cur_chirp;
};

/* Guide for putting paced chirping support into your CC module.
 *
 * 1. Include "paced_chirping.h". If you are experimenting and building PC functions
 *    with a module include "paced_chirping.c" directly. Exports might have to be
 *    commented out.
 *
 * 2. Add a struct paced_chirping in the private data structure of you CC module.
 *    If there isn't enough space for it (most likely the case), make it a pointer
 *    and let PC try to allocate memory for you.
 *
 * 3. When you include this header-file you get a parameter called paced_chirping_enabled.
 *    In your init-function, check this variable and call paced_chirping_init if it is set.
 *    The return value should be stored (if pointer) and indicate whether init was successful.
 *    Return value of NULL indicates error, any other value indicates success.
 *
 * 4. Add paced_chirping_new_chirp to tcp_congestion_ops. You need to implement your own callback
 *    and call paced_chirping_new_chirp yourself.
 *
 * 5. (Currently optional) Call paced_chirping_update on each ack,
 *    either from cong_control or in_ack_event.
 *
 * 6. Disable cwnd and ssthresh updates while paced_chirping_active is true. This can be in
 *    cong_avoid and pkts_acked, so check.
 *
 * 7. (Optional) Call paced_chirping_exit upon loss events. paced_chirping_exit can be
 *    called at any time if you want to abort paced chirping.
 *
 * 8. Call paced_chirping_release from your release function. If you don't have one, implement.
 *
 * 9. Add callback for pkt_acked to a function that calls paced_chirping_pkt_acked.
 */

/*************** Public functions ****************/
/* TCP CC modules must implement new_chirp and release.
 * This text is outdated
 * Additionally either 1 or 2:
 * 1) cong_avoid
 * 2) pkts_acked
 * When either of these functions are called paced_chirping_update must be called.
 * It might be useful to have two version of paced_chirping_update, one for both.
 * Currently pkts_acked implementations have to create a "fake" rate_sample.
 *
 * When new_chirp is called paced_chirping_new_chirp must be called.
 * When release is called paced_chirping_release must be called.
 *
 * paced_chirping_exit should be called upon loss.
 *
 * TCP CC module should not modify cwnd and ssthresh when Paced Chirping is active.
 *
 * paced_chirping_exit should be called upon LOSS
 */

#if IS_ENABLED(CONFIG_PACED_CHIRPING)
struct paced_chirping* paced_chirping_init(struct sock *sk, struct paced_chirping *pc);
bool paced_chirping_new_chirp(struct sock *sk, struct paced_chirping *pc);
void paced_chirping_update(struct sock *sk, struct paced_chirping *pc, const struct rate_sample *rs);
void paced_chirping_pkt_acked(struct sock *sk, struct paced_chirping *pc, struct sk_buff *skb);
int  paced_chirping_active(struct paced_chirping *pc);
void paced_chirping_exit(struct sock *sk, struct paced_chirping *pc, u32 reason);
void paced_chirping_release(struct sock *sk, struct paced_chirping* pc);
u32  paced_chirping_tso_segs(struct sock *sk, struct paced_chirping* pc, u32 tso_segs);

#else

static inline struct paced_chirping* paced_chirping_init(struct sock *sk, struct paced_chirping *pc) { return NULL; }
static inline bool paced_chirping_new_chirp(struct sock *sk, struct paced_chirping *pc) { return true; }
static inline void paced_chirping_update(struct sock *sk, struct paced_chirping *pc, const struct rate_sample *rs) {}
static inline int paced_chirping_active(struct paced_chirping *pc) { return 0; }
static inline void paced_chirping_exit(struct sock *sk, struct paced_chirping *pc, u32 reason) {}
static inline void paced_chirping_release(struct paced_chirping* pc) {}
static inline u32 paced_chirping_tso_segs(struct sock *sk, struct paced_chirping* pc, u32 tso_segs)
{
	return tso_segs;
}
#endif

#endif
