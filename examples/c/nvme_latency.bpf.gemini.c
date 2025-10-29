#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * This tracepoint is hit when an NVMe command is prepared.
 */
SEC("tp/nvme/nvme_setup_cmd")
int handle_nvme_setup_cmd(struct trace_event_raw_nvme_setup_cmd *ctx)
{
	// ctx->cmd is a 'struct nvme_command *'
	// We can read members from it.
	struct nvme_command *cmd = ctx->cmd;
	u8 opcode;

	// Safely read the opcode from the command structure.
	// We use bpf_probe_read_kernel() because 'cmd' is a pointer
	// into kernel memory.
	bpf_probe_read_kernel(&opcode, sizeof(opcode), &cmd->common.opcode);

	bpf_printk("nvme_setup_cmd: PID %d, opcode=0x%x\n", bpf_get_current_pid_tgid() >> 32, opcode);
	return 0;
}

/*
 * This tracepoint is hit when an NVMe request is completed.
 * This is where we get the 'struct request *'
 */
SEC("tp/nvme/nvme_complete_rq")
int handle_nvme_complete_rq(struct trace_event_raw_nvme_complete_rq *ctx)
{
	// ctx->rq is the 'struct request *' you wanted!
	struct request *rq = ctx->rq;

	// Let's read data from the request structure.
	// This requires careful pointer chasing, all using bpf_probe_read_kernel.

	unsigned int data_len;
	struct request_queue *q;
	struct gendisk *disk;
	char disk_name[32]; // BPF_DISK_NAME_LEN is 32

	// 1. Get the data length from the request
	bpf_probe_read_kernel(&data_len, sizeof(data_len), &rq->__data_len);

	// 2. Get the request_queue from the request
	bpf_probe_read_kernel(&q, sizeof(q), &rq->q);

	// 3. Get the gendisk from the request_queue
	bpf_probe_read_kernel(&disk, sizeof(disk), &q->disk);

	// 4. Get the disk_name from the gendisk
	// We use bpf_probe_read_str() for null-terminated strings
	bpf_probe_read_str(&disk_name, sizeof(disk_name), &disk->disk_name);

	bpf_printk("nvme_complete_rq: PID %d, disk=%s, len=%u\n", bpf_get_current_pid_tgid() >> 32, disk_name, data_len);
	return 0;
}
