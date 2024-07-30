
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>


#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define CESAR_SCALE 8
#define CESAR_UNIT (1 << CESAR_SCALE)

#define CESAR_SMALL_SCALE 5	
#define CESAR_SMALL_UNIT (1 << CESAR_SMALL_SCALE)

#define LINE_MARGIN 500

#define INITIAL_SU 5000

#define MAX_PATTERN_COUNT 40

#define MAX_SORTING 3

#define INTERVAL_MIN 30000
#define INTERVAL_MIN_INDEX INTERVAL_MIN/500

#define PATTERN_DECISON_PERIOD 250

static int cesar_mode_outside __read_mostly = 0;
static int cesar_scheduling_unit __read_mostly = 0;
static int cesar_alpha __read_mostly = 2;
static int cesar_beta __read_mostly = 5;
static int cesar_gamma __read_mostly = 8;


module_param(cesar_mode_outside, int, 0644);
MODULE_PARM_DESC(cesar_mode_outside, "mode");
module_param(cesar_scheduling_unit, int, 0644);
MODULE_PARM_DESC(cesar_scheduling_unit, "scheduling_unit");
module_param(cesar_alpha, int, 0644);
MODULE_PARM_DESC(cesar_alpha, "alpha");
module_param(cesar_beta, int, 0644);
MODULE_PARM_DESC(cesar_beta, "beta");
module_param(cesar_gamma, int, 0644);
MODULE_PARM_DESC(cesar_gamma, "alpha");

enum cesar_mode {
	CESAR_STARTUP,	
	CESAR_DRAIN,	
	CESAR_STEADY,
    CESAR_BBR,
};

struct cesar {
	u32	min_rtt_us;	        
	// u32	min_rtt_stamp;	        

	struct minmax bw;

	u16	rtt_cnt;	    
	u32     next_rtt_delivered; 
	u32     mode:3,		    
		prev_ca_state:3,    
		packet_conservation:1, 
		restore_cwnd:1,	     
		round_start:1,	     
		tso_segs_goal:7,     
		pattern_count:16;
	
	u32	pacing_gain:16,	
		full_bw_reached:1,  
		full_bw_cnt:2,	
		cycle_idx:3,	
		su_found:1, 
		gathering_current_scheduling_unit:1,
		pattern_decision_count:8;

	u32 cwnd_est; 

	u16 su;

	u8 *rtt_pattern; 

	u32 previous_rtt; 

	u32 previous_clock; 

	u32	ewma_bw;

	u32 clock_pass;

	u32 scheduling_unit_delivered;

	u32 scheduling_unit_interval_us;

	u32 previous_clock_diff;

	u32 previous_ack;

	u32 previous_previous_rtt;

	u32 previous_bw;
};

// testing
#define BASELINE 200
#define TMP 0

static const int cesar_bw_rtts = 30;

static const u32 cesar_min_rtt_win_sec = 30;

static const int cesar_min_tso_rate = 1200000;

static const int cesar_high_gain  = CESAR_UNIT * 2885 / 1000 + 1;
// static const int cesar_high_gain  = CESAR_UNIT * 2500 / 1000 + 1;

static const int cesar_drain_gain = CESAR_UNIT * 1000 / 2885;
// static const int cesar_drain_gain  = CESAR_UNIT * 1000 / 2500;

static const int cesar_cwnd_gain  = CESAR_UNIT * 2;


static const u32 cesar_cwnd_min_target = 4;

// static const u32 cesar_full_bw_thresh = CESAR_UNIT * 5 / 4;

static const u32 cesar_full_bw_thresh = CESAR_UNIT * 6 / 5;

static const u32 cesar_full_bw_cnt = 3;

static bool cesar_full_bw_reached(const struct sock *sk)
{
	const struct cesar *cesar = inet_csk_ca(sk);

	return cesar->full_bw_reached;
}

static u32 cesar_max_bw(const struct sock *sk)
{
	struct cesar *cesar = inet_csk_ca(sk);

	return minmax_get(&cesar->bw);
}


static u32 cesar_ewma_bw_alpha(const struct sock *sk, const struct rate_sample *rs)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if( !(rs->interval_us > 0) ||  (cesar->su == 0)){
		return cesar->ewma_bw * cesar_alpha;
	}

	if(cesar->mode != CESAR_STEADY){
		return cesar_max_bw(sk);
	}

	return cesar->ewma_bw * cesar_alpha;
}


static u64 cesar_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	rate *= tcp_sk(sk)->mss_cache;
	rate *= gain;
	rate >>= CESAR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}

static u32 cesar_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain,const struct rate_sample *rs)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	u64 rate = 0;
	if(cesar_full_bw_reached(sk)){
		rate = bw;
	} else {
		rate = (u64)1000 * BW_UNIT;
		do_div(rate, 10000);
		if(cesar_max_bw(sk) != 0){
			rate = bw;
		}
	}

	rate = cesar_rate_bytes_per_sec(sk, rate, gain);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}


static void cesar_set_pacing_rate(struct sock *sk, u32 bw, int gain,const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cesar *cesar = inet_csk_ca(sk);
	u32 rate = cesar_bw_to_pacing_rate(sk, bw, gain,rs);

	sk->sk_pacing_rate = rate;
	
}

static u32 cesar_min_tso_segs(struct sock *sk)
{
	return sk->sk_pacing_rate < (cesar_min_tso_rate >> 3) ? 1 : 2;
}

static u32 cesar_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 segs, bytes;

	/* Sort of tcp_tso_autosize() but ignoring
	 * driver provided sk_gso_max_size.
	 */
	bytes = min_t(unsigned long, sk->sk_pacing_rate >> sk->sk_pacing_shift,
		      GSO_MAX_SIZE - 1 - MAX_TCP_HEADER);
	segs = max_t(u32, bytes / tp->mss_cache, cesar_min_tso_segs(sk));

	return min(segs, 0x7FU);
}

static u32 cesar_target_cwnd(struct sock *sk, u32 bw, int gain, const struct rate_sample *rs)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cwnd;
	u64 w;

	if (unlikely(cesar->min_rtt_us == ~0U))	 
		return TCP_INIT_CWND; 

	if(cesar->mode == CESAR_STEADY){
		cwnd = cesar->cwnd_est;
		do_div(cwnd, tp->advmss);

	} else {
		w = (u64)bw * cesar->min_rtt_us;

		cwnd = (((w * gain) >> CESAR_SCALE) + BW_UNIT - 1) / BW_UNIT;

		cwnd += 3 * cesar_tso_segs_goal(sk);

	}
	
	return cwnd;
}

static void cesar_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cesar *cesar = inet_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	if (!acked)
		return;

	cwnd = tp->snd_cwnd;
		
    target_cwnd = cesar_target_cwnd(sk, bw, gain,rs);
    if (cesar_full_bw_reached(sk)){
        cwnd = min(cwnd + acked, target_cwnd);
    } else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND){
        cwnd = cwnd + acked;
    }
    cwnd = max(cwnd, cesar_cwnd_min_target);
	
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
}

static void cesar_reset_startup_mode(struct sock *sk)
{
	struct cesar *cesar = inet_csk_ca(sk);

	cesar->mode = CESAR_STARTUP;
	cesar->pacing_gain = cesar_high_gain;
	// cesar->mode = CESAR_STEADY;
	// cesar->pacing_gain = CESAR_UNIT;
}

static void cesar_reset_steady_mode(struct sock *sk, const struct rate_sample *rs)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	cesar->cwnd_est = tp->snd_cwnd;
	cesar->cwnd_est *= tp->advmss;
	cesar->mode = CESAR_STEADY;
	cesar->pacing_gain = CESAR_UNIT;
	cesar->ewma_bw = cesar_max_bw(sk);
}

static void cesar_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cesar *cesar = inet_csk_ca(sk);
	u64 bw;

	cesar->round_start = 0;
	if (rs->delivered <= 0 || rs->interval_us <= 0)
		return; 

	if (!before(rs->prior_delivered, cesar->next_rtt_delivered)) {
		cesar->next_rtt_delivered = tp->delivered;
		if(cesar->mode != CESAR_STEADY)
			cesar->rtt_cnt++;
		cesar->round_start = 1;
		cesar->packet_conservation = 0;
	}

	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	if(cesar->mode != CESAR_STEADY){
		if (!rs->is_app_limited || bw >= cesar_max_bw(sk)) {
			minmax_running_max(&cesar->bw, 10, cesar->rtt_cnt, bw);
		}

	}
}


static void cesar_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct cesar *cesar = inet_csk_ca(sk);
	u32 bw_thresh;

	if (cesar_full_bw_reached(sk) || !cesar->round_start || rs->is_app_limited)
		return;

	bw_thresh = (u64)cesar->ewma_bw * cesar_full_bw_thresh >> CESAR_SCALE;
	if (cesar_max_bw(sk) >= bw_thresh) {
		cesar->ewma_bw = cesar_max_bw(sk);
		cesar->full_bw_cnt = 0;
		return;
	}
	++cesar->full_bw_cnt;
	cesar->full_bw_reached = cesar->full_bw_cnt >= cesar_full_bw_cnt;
}


static void cesar_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct cesar *cesar = inet_csk_ca(sk);

	if (cesar->mode == CESAR_STARTUP && cesar_full_bw_reached(sk)) {
		cesar->mode = CESAR_DRAIN;	/* drain queue we created */
		cesar->pacing_gain = cesar_drain_gain;	/* pace slow to drain */
		cesar_reset_steady_mode(sk,rs);
	}
}

static void cesar_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cesar *cesar = inet_csk_ca(sk);
	bool filter_expired;

	// filter_expired = after(tcp_jiffies32,
	// 		       cesar->min_rtt_stamp + cesar_min_rtt_win_sec * HZ);
	
	if (rs->rtt_us > 0 &&
		((rs->rtt_us <= cesar->min_rtt_us))) {
		cesar->min_rtt_us = rs->rtt_us;
		// cesar->min_rtt_stamp = tcp_jiffies32;
	}

}

void cesar_rtt_pattern_reset(struct sock *sk)
{
	struct cesar *cesar = inet_csk_ca(sk);
	u8 i;
	for(i = 0 ; i < MAX_PATTERN_COUNT ; i++){
		cesar->rtt_pattern[i] = 0;
	}
	cesar->pattern_count = 0;
}

void cesar_pattern_decision(struct sock *sk, const struct rate_sample *rs, u32 clock_diff)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if(cesar->pattern_count < PATTERN_DECISON_PERIOD){
		return;
	}

	u8 large_pattern_index[MAX_SORTING];
	u8 large_pattern_value[MAX_SORTING];

	u8 i;
	u8 j;
	u8 k;
	u8 max;
	u8 index;
	
	cesar->rtt_pattern[0] = 0;
	cesar->rtt_pattern[1] = 0;
	cesar->rtt_pattern[2] = 0;
	cesar->rtt_pattern[4] = 0;
	// find the 1~5th pattern index that appeared a lot (large_pattern_index) 
	for(i = 0 ; i < MAX_SORTING ; i++){
		max = cesar->rtt_pattern[0];
		index = 0;
		j = 0;
		for (j = 5; j < MAX_PATTERN_COUNT; j++) {
			if (cesar->rtt_pattern[j] > max) {
				max = cesar->rtt_pattern[j];
				index = j;
			}
		}
		
		large_pattern_index[i] = index;
		large_pattern_value[i] = max;

		cesar->rtt_pattern[index] = 0;
		
		if(index >= 4){
			cesar->rtt_pattern[index-1] = 0;
			cesar->rtt_pattern[index-2] = 0;
			cesar->rtt_pattern[index-3] = 0;
			cesar->rtt_pattern[index-4] = 0;
		} else {
			for (j = 0; j < index; j++) {
				cesar->rtt_pattern[j] = 0;
			}
		}

		if(index <= MAX_PATTERN_COUNT - 5){
			cesar->rtt_pattern[index+1] = 0;
			cesar->rtt_pattern[index+2] = 0;
			cesar->rtt_pattern[index+3] = 0;
			cesar->rtt_pattern[index+4] = 0;
		} else {
			for (j = MAX_PATTERN_COUNT - 1; j > index; j--) {
				cesar->rtt_pattern[j] = 0;
			}
		}
	}
	
	// printk(KERN_WARNING "TEST: %d large_pattern i %u v %u i %u v %u i %u v %u \n", ntohs((tp->inet_conn).icsk_inet.inet_sport), 
	// LINE_MARGIN * large_pattern_index[0],large_pattern_value[0],LINE_MARGIN * large_pattern_index[1],large_pattern_value[1],LINE_MARGIN * large_pattern_index[2],large_pattern_value[2]
	// );

	if(large_pattern_value[0] >= 8){
		cesar->mode = CESAR_STEADY;
		cesar->su = LINE_MARGIN * large_pattern_index[0];

		if((large_pattern_index[0] == 10)){
			if( (large_pattern_index[1] == 5)
			&& (large_pattern_value[1] >= (large_pattern_value[0] / 2)) ){
				cesar->su = 2500;
			} else if( (large_pattern_index[2] == 5) 
				&& (large_pattern_value[2] >= (large_pattern_value[0] / 2)) ){
				cesar->su = 2500;
			}
		}

		if((large_pattern_index[0] == 20)){
			if(large_pattern_index[1] == 10){
				cesar->su = 5000;
			} else if((large_pattern_index[2] == 10) 
				&& (large_pattern_value[2] >= (large_pattern_value[0] / 2))){
				cesar->su = 5000;
			}
		}

		if(cesar->su == 4500){
			cesar->su = 5000;
		} else if(cesar->su == 7500){
			cesar->su = 8000;
		}

	} else {
        if((large_pattern_value[0] == 0) || (large_pattern_value[1] == 0)){
           cesar->mode = CESAR_BBR;
           cesar->su = INITIAL_SU;
        } else {
            if((large_pattern_index[0] % large_pattern_index[1]) != 0){
                if( ((large_pattern_index[0] % (large_pattern_index[1] + 1)) != 0)
                &&  ((large_pattern_index[0] % (large_pattern_index[1] - 1)) != 0) ){
                    cesar->mode = CESAR_BBR;
                    cesar->su = INITIAL_SU;
                }  
            }
        }
    }

	cesar_rtt_pattern_reset(sk);

}

void cesar_pattern_detection(struct sock *sk, const struct rate_sample *rs, u32 clock_diff)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	u32 pattern_idx;
	pattern_idx = (clock_diff / LINE_MARGIN);
	
	if((pattern_idx >= MAX_PATTERN_COUNT)){
		return;
	} else {
		cesar->rtt_pattern[pattern_idx] += 1;
		if(pattern_idx != (MAX_PATTERN_COUNT - 1)){
			cesar->rtt_pattern[pattern_idx + 1] += 1;
		}
		cesar->pattern_count += 1;
	}
}

static void cesar_update_model(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cesar *cesar = inet_csk_ca(sk);

	cesar_update_bw(sk, rs);
	cesar_check_full_bw_reached(sk, rs);
	cesar_check_drain(sk, rs);
	cesar_update_min_rtt(sk, rs);
}

static void cesar_do_adjustment(struct sock *sk,  const struct rate_sample *rs, u32 current_clock, u32 ack){
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	u64 scheduling_unit_bw = (u64)cesar->scheduling_unit_delivered * BW_UNIT;
	do_div(scheduling_unit_bw, cesar->scheduling_unit_interval_us);
	
	u32 gain = 0;
	if((rs->interval_us > (cesar->min_rtt_us + TMP * cesar->su))){
		gain = 100 * (rs->interval_us - (cesar->min_rtt_us + TMP * cesar->su));
		do_div(gain, (rs->interval_us));

		u32 pacing_gain  = CESAR_UNIT;
		pacing_gain = pacing_gain * (BASELINE - gain) / BASELINE;
		cesar->pacing_gain = pacing_gain;
	} 

	if(
	(cesar->previous_rtt <= cesar->previous_previous_rtt)
	)
	{
		u32 current_cwnd = cesar->cwnd_est;
		u64 amount_of_modification = 0;

		amount_of_modification = cesar->ewma_bw;


		if((rs->interval_us > (cesar->min_rtt_us + TMP * cesar->su))){
			amount_of_modification = amount_of_modification * (BASELINE - gain) / BASELINE;
		} 

		amount_of_modification *= (cesar->su);

		amount_of_modification *= tp->advmss;
		amount_of_modification >>= BW_SCALE;
		
		amount_of_modification *= cesar->previous_previous_rtt - cesar->previous_rtt;

		do_div(amount_of_modification, cesar->previous_previous_rtt - cesar->min_rtt_us);

		if((cesar->ewma_bw > cesar->previous_bw)
		){
			u64 over_rtt = 0;
			u64 beta = CESAR_SMALL_UNIT * cesar_beta;

			u64 cwnd_origin = cesar->cwnd_est;
			u64 cwnd =  cesar->cwnd_est;

			cwnd *= cesar->min_rtt_us;
			
			u64 over_rtt_tmp = 0;
			
			if(cesar->previous_rtt > cesar->min_rtt_us)
				over_rtt_tmp = cesar->previous_rtt - cesar->min_rtt_us;

            over_rtt_tmp *= cesar->ewma_bw - cesar->previous_bw;
            do_div(over_rtt_tmp, cesar->ewma_bw);
			
			do_div(cwnd, cesar->min_rtt_us + over_rtt_tmp);

			cwnd *= beta;
			cwnd >>= CESAR_SMALL_SCALE;
			do_div(cwnd, 100);

			cwnd_origin *= (100 * CESAR_SMALL_UNIT -beta);
			do_div(cwnd_origin, 100 * CESAR_SMALL_UNIT);
			
			cesar->cwnd_est = cwnd_origin + cwnd;
		}

		cesar->cwnd_est += amount_of_modification;

		cesar->cwnd_est = max(current_cwnd, cesar->cwnd_est);
	} else if(		
	(cesar->previous_rtt > cesar->previous_previous_rtt)
	){
		u64 over_rtt = 0;
		u64 beta = CESAR_SMALL_UNIT * cesar_beta;

		u64 cwnd_origin = cesar->cwnd_est;
		u64 cwnd =  cesar->cwnd_est;

		cwnd *= cesar->min_rtt_us;
		
		u64 over_rtt_tmp = 0;

		over_rtt = cesar->previous_rtt - cesar->previous_previous_rtt;
		
		if(cesar->previous_rtt > cesar->min_rtt_us)
			over_rtt_tmp = cesar->previous_rtt - cesar->min_rtt_us;

		if(cesar->ewma_bw > cesar->previous_bw){
			over_rtt_tmp *= cesar->ewma_bw - cesar->previous_bw;
			do_div(over_rtt_tmp, cesar->ewma_bw);
		} else {
			over_rtt_tmp = 0;
		}

		if(cesar->previous_bw > scheduling_unit_bw){
        	over_rtt *= scheduling_unit_bw;
        	do_div(over_rtt, cesar->previous_bw);
		}
		

		do_div(cwnd, cesar->min_rtt_us + over_rtt_tmp + over_rtt);

		cwnd *= beta;
		cwnd >>= CESAR_SMALL_SCALE;
		do_div(cwnd, 100);

		cwnd_origin *= (100 * CESAR_SMALL_UNIT -beta);
		do_div(cwnd_origin, 100 * CESAR_SMALL_UNIT);
		
		cesar->cwnd_est = cwnd_origin + cwnd;
		
	} 

	cesar->ewma_bw -= cesar->ewma_bw / cesar_gamma;
	cesar->ewma_bw += cesar->previous_bw / cesar_gamma;

	cesar->previous_previous_rtt = cesar->previous_rtt;
}

static void cesar_do_reset(struct sock *sk,  const struct rate_sample *rs){
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	cesar->gathering_current_scheduling_unit = 0;
	cesar->scheduling_unit_interval_us = 0;
	cesar->scheduling_unit_delivered = 0;
	cesar->clock_pass = 0;
}

static void cesar_scheduling_unit_adjust(struct sock *sk, const struct rate_sample *rs,u32 current_clock, u32 ack)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if(!(rs->rtt_us > 0) || !(cesar->previous_rtt > 0) || (cesar->min_rtt_us > rs->rtt_us)){
		return;
	}

	if(cesar_scheduling_unit == 0){
		cesar_pattern_detection(sk,rs,current_clock -cesar->previous_clock);
		cesar_pattern_decision(sk,rs,current_clock -cesar->previous_clock);
	} else {
		cesar->su = cesar_scheduling_unit;
	}

	u64 bw = 0;
	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	if((cesar->mode != CESAR_STEADY)){
		cesar->previous_clock = current_clock;
		return;
	}


	u32 margin = LINE_MARGIN * 2;
	if(cesar->su <= 3000){
		margin = LINE_MARGIN;
	}
	bool clock_saving = 0;
	u32 previous_clock_diff = cesar->previous_clock_diff;
	u32 current_clock_diff = current_clock - cesar->previous_clock;	
	current_clock_diff += cesar->clock_pass;
	previous_clock_diff += cesar->clock_pass;

	if((previous_clock_diff >= (cesar->su - margin))
	&& (current_clock_diff < (cesar->su - margin))){
		cesar->scheduling_unit_delivered += cesar->previous_ack;
		cesar->scheduling_unit_interval_us = ((previous_clock_diff + margin) / cesar->su) * cesar->su;
		cesar->gathering_current_scheduling_unit = 1;

		if((abs(cesar->previous_clock_diff - cesar->scheduling_unit_interval_us) > margin)
		&& (cesar->previous_clock_diff >= (cesar->su + LINE_MARGIN))
		&& (cesar->previous_clock_diff > cesar->scheduling_unit_interval_us)){
			cesar->clock_pass +=  cesar->previous_clock_diff - cesar->scheduling_unit_interval_us;
		}

		// testing
		cesar->scheduling_unit_interval_us = previous_clock_diff;

	} else if((previous_clock_diff >= (cesar->su - margin))
	&& (current_clock_diff >= (cesar->su - margin))){
		cesar->scheduling_unit_delivered += cesar->previous_ack;
		cesar->scheduling_unit_interval_us = (( previous_clock_diff + margin) / cesar->su) * cesar->su;
		
		// testing
		cesar->scheduling_unit_interval_us = previous_clock_diff;

		cesar_do_adjustment(sk,rs,current_clock,ack);
		cesar_do_reset(sk,rs);

	} else if((previous_clock_diff < (cesar->su - margin))
	&& (current_clock_diff >= (cesar->su - margin))){
		if(cesar->gathering_current_scheduling_unit){
			cesar->scheduling_unit_delivered += cesar->previous_ack;
			cesar_do_adjustment(sk,rs,current_clock,ack);
			cesar_do_reset(sk,rs);
			if((current_clock - cesar->previous_clock) < (cesar->su - margin)){
				clock_saving = 1;
			}
		} 

	} else if((previous_clock_diff < (cesar->su - margin))
	&& (current_clock_diff < (cesar->su - margin))){
		if(cesar->gathering_current_scheduling_unit){
			cesar->scheduling_unit_delivered += cesar->previous_ack;
			cesar->clock_pass +=  cesar->previous_clock_diff;
		}
	}

	// printk(KERN_WARNING "****TEST: %d clock_pass %u delivered %u interval %u current_clock %u previous clock %u\n", ntohs((tp->inet_conn).icsk_inet.inet_sport), 
	// 	cesar->clock_pass, cesar->scheduling_unit_delivered, cesar->scheduling_unit_interval_us,
	// 	current_clock_diff, cesar->previous_clock_diff);

	if(clock_saving)
		cesar->previous_clock_diff = current_clock_diff;
	else
		cesar->previous_clock_diff = current_clock - cesar->previous_clock;
	cesar->previous_ack = ack;
	cesar->previous_clock = current_clock;
	cesar->previous_bw = bw;
	cesar->previous_rtt = rs->rtt_us;
}

static void cesar_main(struct sock *sk, const struct rate_sample *rs)
{
	struct cesar *cesar = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 bw;

	cesar_update_model(sk, rs);

	if(cesar_mode_outside == 1){
		printk(KERN_WARNING "DEBUG: %d %u rtt %u min %u current_clock %u previous_rtt %u period %u ewma %d max %u bound_max %u inter %u deliver %u clock %u snd %u condition %u pacing %u beta %u g %u ack %u mss %u app %u %u | %d \n", ntohs((tp->inet_conn).icsk_inet.inet_sport), 
		cesar->cwnd_est, rs->rtt_us, cesar->min_rtt_us, 
		tp->tcp_mstamp, cesar->previous_rtt, 
		cesar->su, cesar->ewma_bw, cesar_max_bw(sk), 0,
		rs->interval_us, rs->delivered, tp->tcp_mstamp - cesar->previous_clock , tp->snd_cwnd,0,sk->sk_pacing_rate, 0,
		cesar->pacing_gain,rs->acked_sacked,tp->advmss, 
		rs->is_app_limited, 0,
		cesar->mode);
	}

    cesar_scheduling_unit_adjust(sk,rs,tp->tcp_mstamp,rs->acked_sacked);

	bw = cesar_ewma_bw_alpha(sk,rs);

    if(cesar->mode == CESAR_BBR){
        cesar->pacing_gain = CESAR_UNIT;
    }
	cesar_set_pacing_rate(sk, bw, cesar->pacing_gain,rs);
	cesar_set_cwnd(sk, rs, rs->acked_sacked, bw, cesar_cwnd_gain);
}

static void cesar_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cesar *cesar = inet_csk_ca(sk);

	cesar->tso_segs_goal = 0;	
	cesar->rtt_cnt = 0;
	cesar->next_rtt_delivered = 0;
	cesar->prev_ca_state = TCP_CA_Open;
	cesar->packet_conservation = 0;

	cesar->min_rtt_us = 100000;
	// cesar->min_rtt_stamp = tcp_jiffies32;

	minmax_reset(&cesar->bw, cesar->rtt_cnt, 0); 

	cesar->restore_cwnd = 0;
	cesar->round_start = 0;
	cesar->full_bw_reached = 0;
	cesar->ewma_bw = 0;
	cesar->full_bw_cnt = 0;
	cesar->cycle_idx = 0;
	cesar_reset_startup_mode(sk);

	cesar->cwnd_est = 1 * tp->advmss;

	cesar->su = INITIAL_SU;

	cesar->pattern_decision_count = 0;

	cesar->su_found = 0;

	cesar->previous_rtt = 100000;

	cesar->previous_clock = 1;

	cesar->previous_clock_diff = 0;

	// cesar->every_previous_rtt = 0;

	cesar->previous_bw = 0;

	cesar->rtt_pattern = (u8*)kmalloc(MAX_PATTERN_COUNT * sizeof(u8), GFP_KERNEL);
	if (!(cesar->rtt_pattern)) {
    	printk(KERN_WARNING "DEBUG: %d could not allocate array memory\n", ntohs((tp->inet_conn).icsk_inet.inet_sport));
    } else {
		printk(KERN_WARNING "DEBUG: %d successfully allocate array memory\n", ntohs((tp->inet_conn).icsk_inet.inet_sport));
    
	}
    memset(cesar->rtt_pattern, 0, MAX_PATTERN_COUNT * sizeof(u8));
	cesar_rtt_pattern_reset(sk);

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

void cesar_release(struct sock *sk) {
    struct cesar *cesar = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
	
    if (cesar->rtt_pattern != NULL) {
        kfree(cesar->rtt_pattern);
        cesar->rtt_pattern = NULL;
		printk(KERN_WARNING "DEBUG: %d release memory\n", ntohs((tp->inet_conn).icsk_inet.inet_sport));
    }
}

static u32 cesar_sndbuf_expand(struct sock *sk)
{
	return 3;
}

static u32 cesar_undo_cwnd(struct sock *sk)
{
	struct cesar *cesar = inet_csk_ca(sk);

	cesar->full_bw_cnt = 0;
	return tcp_sk(sk)->snd_cwnd;
}

static u32 cesar_ssthresh(struct sock *sk)
{
	// cesar_save_cwnd(sk);
	return TCP_INFINITE_SSTHRESH;	
}

static void cesar_set_state(struct sock *sk, u8 new_state)
{
	struct cesar *cesar = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };
		cesar->prev_ca_state = TCP_CA_Loss;
	}
}

static void cesar_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if(sample->rtt_us <= 0){
		return;
	}

	printk(KERN_WARNING "LOG: %d cwnd %u rtt %u mss %u byte_ack %u \n", ntohs((tp->inet_conn).icsk_inet.inet_sport), 
	tp->snd_cwnd, sample->rtt_us, tp->advmss,tp->bytes_acked);
	
}

static struct tcp_congestion_ops tcp_cesar_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "cesar",
	.owner		= THIS_MODULE,
	.init		= cesar_init,
	.cong_control	= cesar_main,
	.sndbuf_expand	= cesar_sndbuf_expand,
	.undo_cwnd	= cesar_undo_cwnd,
	.ssthresh	= cesar_ssthresh,
	.min_tso_segs	= cesar_min_tso_segs,
	.set_state	= cesar_set_state,
	.pkts_acked = cesar_acked,
	.release = cesar_release,
};

static int __init cesar_register(void)
{
	BUILD_BUG_ON(sizeof(struct cesar) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_cesar_cong_ops);
}

static void __exit cesar_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_cesar_cong_ops);
}

module_init(cesar_register);
module_exit(cesar_unregister);

MODULE_AUTHOR("Juhun Shin <jhshin@netlab.snu.ac.kr>");
MODULE_AUTHOR("Goodsol Lee <gslee2@netlab.snu.ac.kr>");
MODULE_AUTHOR("Jeongyeup Paek <jpaek@cau.ac.kr>");
MODULE_AUTHOR("Saewoong Bahk <sbahk@snu.ac.kr>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP César for cellular networks");