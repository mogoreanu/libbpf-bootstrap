#include "vmlinux.h"
#include "nvme_latency.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include <linux/blk-mq.h>
// #include <linux/blkdev.h>
// #include <linux/nvme.h>
// #include <linux/cdev.h>
// #include <linux/nvme_ioctl.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

struct nvme_fault_inject {
#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
  struct fault_attr attr;
  struct dentry *parent;
  bool dont_retry;  /* DNR, do not retry */
  u16 status;    /* status code */
#endif
};

struct nvme_ns {
  struct list_head list;

  struct nvme_ctrl *ctrl;
  struct request_queue *queue;
  struct gendisk *disk;
#ifdef CONFIG_NVME_MULTIPATH
  enum nvme_ana_state ana_state;
  u32 ana_grpid;
#endif
  struct list_head siblings;
  struct kref kref;
  struct nvme_ns_head *head;

  unsigned long flags;
#define NVME_NS_REMOVING    0
#define NVME_NS_ANA_PENDING    2
#define NVME_NS_FORCE_RO    3
#define NVME_NS_READY      4
#define NVME_NS_SYSFS_ATTR_LINK  5

  struct cdev    cdev;
  struct device    cdev_device;

  struct nvme_fault_inject fault_inject;
};

typedef __u32 req_flags_t;

enum mq_rq_state {
	MQ_RQ_IDLE		= 0,
	MQ_RQ_IN_FLIGHT		= 1,
	MQ_RQ_COMPLETE		= 2,
};

typedef enum rq_end_io_ret (rq_end_io_fn)(struct request *, blk_status_t);

/**
 * struct sbitmap_word - Word in a &struct sbitmap.
 */
struct sbitmap_word {
	/**
	 * @word: word holding free bits
	 */
	unsigned long word;

	/**
	 * @cleared: word holding cleared bits
	 */
	unsigned long cleared ____cacheline_aligned_in_smp;

	/**
	 * @swap_lock: serializes simultaneous updates of ->word and ->cleared
	 */
	raw_spinlock_t swap_lock;
} ____cacheline_aligned_in_smp;

/**
 * struct sbitmap - Scalable bitmap.
 *
 * A &struct sbitmap is spread over multiple cachelines to avoid ping-pong. This
 * trades off higher memory usage for better scalability.
 */
struct sbitmap {
	/**
	 * @depth: Number of bits used in the whole bitmap.
	 */
	unsigned int depth;

	/**
	 * @shift: log2(number of bits used per word)
	 */
	unsigned int shift;

	/**
	 * @map_nr: Number of words (cachelines) being used for the bitmap.
	 */
	unsigned int map_nr;

	/**
	 * @round_robin: Allocate bits in strict round-robin order.
	 */
	bool round_robin;

	/**
	 * @map: Allocated bitmap.
	 */
	struct sbitmap_word *map;

	/*
	 * @alloc_hint: Cache of last successfully allocated or freed bit.
	 *
	 * This is per-cpu, which allows multiple users to stick to different
	 * cachelines until the map is exhausted.
	 */
	unsigned int __percpu *alloc_hint;
};


struct blk_mq_hw_ctx {
	struct {
		/** @lock: Protects the dispatch list. */
		spinlock_t		lock;
		/**
		 * @dispatch: Used for requests that are ready to be
		 * dispatched to the hardware but for some reason (e.g. lack of
		 * resources) could not be sent to the hardware. As soon as the
		 * driver can send new requests, requests at this list will
		 * be sent first for a fairer dispatch.
		 */
		struct list_head	dispatch;
		 /**
		  * @state: BLK_MQ_S_* flags. Defines the state of the hw
		  * queue (active, scheduled to restart, stopped).
		  */
		unsigned long		state;
	} ____cacheline_aligned_in_smp;

	/**
	 * @run_work: Used for scheduling a hardware queue run at a later time.
	 */
	struct delayed_work	run_work;
	/** @cpumask: Map of available CPUs where this hctx can run. */
	cpumask_var_t		cpumask;
	/**
	 * @next_cpu: Used by blk_mq_hctx_next_cpu() for round-robin CPU
	 * selection from @cpumask.
	 */
	int			next_cpu;
	/**
	 * @next_cpu_batch: Counter of how many works left in the batch before
	 * changing to the next CPU.
	 */
	int			next_cpu_batch;

	/** @flags: BLK_MQ_F_* flags. Defines the behaviour of the queue. */
	unsigned long		flags;

	/**
	 * @sched_data: Pointer owned by the IO scheduler attached to a request
	 * queue. It's up to the IO scheduler how to use this pointer.
	 */
	void			*sched_data;
	/**
	 * @queue: Pointer to the request queue that owns this hardware context.
	 */
	struct request_queue	*queue;
	/** @fq: Queue of requests that need to perform a flush operation. */
	struct blk_flush_queue	*fq;

	/**
	 * @driver_data: Pointer to data owned by the block driver that created
	 * this hctx
	 */
	void			*driver_data;

	/**
	 * @ctx_map: Bitmap for each software queue. If bit is on, there is a
	 * pending request in that software queue.
	 */
	struct sbitmap		ctx_map;

	/**
	 * @dispatch_from: Software queue to be used when no scheduler was
	 * selected.
	 */
	struct blk_mq_ctx	*dispatch_from;
	/**
	 * @dispatch_busy: Number used by blk_mq_update_dispatch_busy() to
	 * decide if the hw_queue is busy using Exponential Weighted Moving
	 * Average algorithm.
	 */
	unsigned int		dispatch_busy;

	/** @type: HCTX_TYPE_* flags. Type of hardware queue. */
	unsigned short		type;
	/** @nr_ctx: Number of software queues. */
	unsigned short		nr_ctx;
	/** @ctxs: Array of software queues. */
	struct blk_mq_ctx	**ctxs;

	/** @dispatch_wait_lock: Lock for dispatch_wait queue. */
	spinlock_t		dispatch_wait_lock;
	/**
	 * @dispatch_wait: Waitqueue to put requests when there is no tag
	 * available at the moment, to wait for another try in the future.
	 */
	wait_queue_entry_t	dispatch_wait;

	/**
	 * @wait_index: Index of next available dispatch_wait queue to insert
	 * requests.
	 */
	atomic_t		wait_index;

	/**
	 * @tags: Tags owned by the block driver. A tag at this set is only
	 * assigned when a request is dispatched from a hardware queue.
	 */
	struct blk_mq_tags	*tags;
	/**
	 * @sched_tags: Tags owned by I/O scheduler. If there is an I/O
	 * scheduler associated with a request queue, a tag is assigned when
	 * that request is allocated. Else, this member is not used.
	 */
	struct blk_mq_tags	*sched_tags;

	/** @numa_node: NUMA node the storage adapter has been connected to. */
	unsigned int		numa_node;
	/** @queue_num: Index of this hardware queue. */
	unsigned int		queue_num;

	/**
	 * @nr_active: Number of active requests. Only used when a tag set is
	 * shared across request queues.
	 */
	atomic_t		nr_active;

	/** @cpuhp_online: List to store request if CPU is going to die */
	struct hlist_node	cpuhp_online;
	/** @cpuhp_dead: List to store request if some CPU die. */
	struct hlist_node	cpuhp_dead;
	/** @kobj: Kernel object for sysfs. */
	struct kobject		kobj;

#ifdef CONFIG_BLK_DEBUG_FS
	/**
	 * @debugfs_dir: debugfs directory for this hardware queue. Named
	 * as cpu<cpu_number>.
	 */
	struct dentry		*debugfs_dir;
	/** @sched_debugfs_dir:	debugfs directory for the scheduler. */
	struct dentry		*sched_debugfs_dir;
#endif

	/**
	 * @hctx_list: if this hctx is not in use, this is an entry in
	 * q->unused_hctx_list.
	 */
	struct list_head	hctx_list;
};

struct request {
	struct request_queue *q;
	struct blk_mq_ctx *mq_ctx;
	struct blk_mq_hw_ctx *mq_hctx;

	blk_opf_t cmd_flags;		/* op and common flags */
	req_flags_t rq_flags;

	int tag;
	int internal_tag;

	unsigned int timeout;

	/* the following two fields are internal, NEVER access directly */
	unsigned int __data_len;	/* total data len */
	sector_t __sector;		/* sector cursor */

	struct bio *bio;
	struct bio *biotail;

	union {
		struct list_head queuelist;
		struct request *rq_next;
	};

	struct block_device *part;
#ifdef CONFIG_BLK_RQ_ALLOC_TIME
	/* Time that the first bio started allocating this request. */
	u64 alloc_time_ns;
#endif
	/* Time that this request was allocated for this IO. */
	u64 start_time_ns;
	/* Time that I/O was submitted to the device. */
	u64 io_start_time_ns;

#ifdef CONFIG_BLK_WBT
	unsigned short wbt_flags;
#endif
	/*
	 * rq sectors used for blk stats. It has the same value
	 * with blk_rq_sectors(rq), except that it never be zeroed
	 * by completion.
	 */
	unsigned short stats_sectors;

	/*
	 * Number of scatter-gather DMA addr+len pairs after
	 * physical address coalescing is performed.
	 */
	unsigned short nr_phys_segments;
	unsigned short nr_integrity_segments;

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
	struct bio_crypt_ctx *crypt_ctx;
	struct blk_crypto_keyslot *crypt_keyslot;
#endif

	enum mq_rq_state state;
	atomic_t ref;

	unsigned long deadline;

	/*
	 * The hash is used inside the scheduler, and killed once the
	 * request reaches the dispatch list. The ipi_list is only used
	 * to queue the request for softirq completion, which is long
	 * after the request has been unhashed (and even removed from
	 * the dispatch list).
	 */
	union {
		struct hlist_node hash;	/* merge hash */
		struct llist_node ipi_list;
	};

	/*
	 * The rb_node is only used inside the io scheduler, requests
	 * are pruned when moved to the dispatch queue. special_vec must
	 * only be used if RQF_SPECIAL_PAYLOAD is set, and those cannot be
	 * insert into an IO scheduler.
	 */
	union {
		struct rb_node rb_node;	/* sort/lookup */
		struct bio_vec special_vec;
	};

	/*
	 * Three pointers are available for the IO schedulers, if they need
	 * more they have to dynamically allocate it.
	 */
	struct {
		struct io_cq		*icq;
		void			*priv[2];
	} elv;

	struct {
		unsigned int		seq;
		rq_end_io_fn		*saved_end_io;
	} flush;

	u64 fifo_time;

	/*
	 * completion callback.
	 */
	rq_end_io_fn *end_io;
	void *end_io_data;
};

static inline u16 nvme_req_qid(struct request *req) {
  if (!req->q->queuedata)
    return 0;

  return req->mq_hctx->queue_num + 1;
}

SEC("tp/nvme/nvme_setup_cmd")
int nvme_setup_cmd_return(struct pt_regs *ctx, struct nvme_ns *ns,
                          struct request *req) {
  // int ret = PT_REGS_RC(ctx)
  u16 qid = nvme_req_qid(req);
  struct nvme_request* nreq = nvme_req(req);
  struct nvme_command* nvme_cmd = nreq->cmd;
  int ctrl_id = nreq->ctrl->instance;
  // ns->disk->disk_name
  if (vlog) {
    bpf_trace_printk(
        "nvme_setup_cmd qid: %d opcode: %x cid: %d\\n",
        qid, nvme_cmd->common.opcode,
        nvme_cmd->common.command_id);
  }
  u64 nsec = bpf_ktime_get_ns();
  in_flight_reqs.update(&req, &nsec);

  return 0;
}

// SEC("tp/nvme/nvme_complete_rq")
// int nvme_complete_rq(struct pt_regs *ctx, struct request *req) {
//   // dist.increment(bpf_log2l(req->__data_len / 1024));
//   struct nvme_request* nreq = nvme_req(req);
//   struct nvme_command* nvme_cmd = nreq->cmd;
//   u64 nsec = bpf_ktime_get_ns();

//   u64* start_nsec_ptr = in_flight_reqs.lookup(&req);
//   if (start_nsec_ptr) {
//     u64 delta = nsec - *start_nsec_ptr;
//     req_lat_hist_us.increment(bpf_log2l(delta / 1000));
//     in_flight_reqs.delete(&req);
//   }
//   if (vlog) {
//     bpf_trace_printk("nvme_complete_rq opcode: %x cid: %d\\n",
//                      nvme_cmd->common.opcode, nvme_cmd->common.command_id);
//   }

//   return 0;
// }


// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
// {
// 	struct task_struct *task;
// 	unsigned fname_off;
// 	struct event *e;
// 	pid_t pid;
// 	u64 ts;

// 	/* remember time exec() was executed for this PID */
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	ts = bpf_ktime_get_ns();
// 	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

// 	/* don't emit exec events when minimum duration is specified */
// 	if (min_duration_ns)
// 		return 0;

// 	/* reserve sample from BPF ringbuf */
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();

// 	e->exit_event = false;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));

// 	fname_off = ctx->__data_loc_filename & 0xFFFF;
// 	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

// 	/* successfully submit it to user-space for post-processing */
// 	bpf_ringbuf_submit(e, 0);
// 	return 0;
// }

// SEC("tp/sched/sched_process_exit")
// int handle_exit(struct trace_event_raw_sched_process_template *ctx)
// {
// 	struct task_struct *task;
// 	struct event *e;
// 	pid_t pid, tid;
// 	u64 id, ts, *start_ts, duration_ns = 0;

// 	/* get PID and TID of exiting thread/process */
// 	id = bpf_get_current_pid_tgid();
// 	pid = id >> 32;
// 	tid = (u32)id;

// 	/* ignore thread exits */
// 	if (pid != tid)
// 		return 0;

// 	/* if we recorded start of the process, calculate lifetime duration */
// 	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
// 	if (start_ts)
// 		duration_ns = bpf_ktime_get_ns() - *start_ts;
// 	else if (min_duration_ns)
// 		return 0;
// 	bpf_map_delete_elem(&exec_start, &pid);

// 	/* if process didn't live long enough, return early */
// 	if (min_duration_ns && duration_ns < min_duration_ns)
// 		return 0;

// 	/* reserve sample from BPF ringbuf */
// 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (!e)
// 		return 0;

// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();

// 	e->exit_event = true;
// 	e->duration_ns = duration_ns;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));

// 	/* send data to user-space for post-processing */
// 	bpf_ringbuf_submit(e, 0);
// 	return 0;
// }
