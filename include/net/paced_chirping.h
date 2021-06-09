#ifndef __NET_PACED_CHIRPING_H
#define __NET_PACED_CHIRPING_H

#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>

enum {
	UNUSED,
	INTERNAL_PACING,
	FQ_PACING
};

struct paced_chirping_ext {
	u16 chirp_number;
	u8 packets;

	u64 scheduled_gap;
};

struct paced_chirping_cache {
	u32 srtt;
	u32 cwnd;
	u32 reordering;
};

void paced_chirping_cache_get(struct sock *sk, struct paced_chirping_cache *pc_cache);

#if IS_ENABLED(CONFIG_PACED_CHIRPING)

static inline bool paced_chirping_is_chirping(struct tcp_sock *tp)
{
	return tp->is_chirping;
}

void paced_chirping_chirp_gap(struct sock *sk, struct sk_buff *skb);
bool paced_chirping_new_chirp_check(struct sock *sk);

static inline bool paced_chirping_new_chirp_and_send_check(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!paced_chirping_is_chirping(tp))
		return false;

	return paced_chirping_new_chirp_check(sk);
}

#else

static inline bool paced_chirping_is_chirping(struct tcp_sock *tp)
{
        return false;
}

static inline void paced_chirping_chirp_gap(struct sock *sk,
					    struct sk_buff *skb) {}

static inline bool paced_chirping_new_chirp_and_send_check(struct sock *sk)
{
	return false;
}

#endif

#endif /* __NET_PACED_CHIRPING_H */
