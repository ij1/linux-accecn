#ifndef __NET_PACED_CHIRPING_H
#define __NET_PACED_CHIRPING_H

#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>

enum {
	UNUSED,
	INTERAL_PACING,
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

static inline int packed_chirping_packet_in_chirp(struct sk_buff *skb)
{
	return skb_ext_find(skb, SKB_EXT_PACED_CHIRPING) != NULL;
}

#else

static inline int packed_chirping_packet_in_chirp(struct sk_buff *skb)
{
	return false;
}

#endif

#endif /* __NET_PACED_CHIRPING_H */
