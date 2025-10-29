#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "nvme_latency.h"
#include "nvme_latency.skel.h"

/*
make nvme_latency
sudo ./nvme_latency
sudo cat /sys/kernel/debug/tracing/trace_pipe
*/

// static struct env {
// 	bool verbose;
// 	long min_duration_ms;
// } env;

const char *argp_program_version = "nvme_latency 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF nvme_latency demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./nvme_latency [-d <min-duration-ms>] [-v]\n";

// static const struct argp_option opts[] = {
// 	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
// 	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
// 	{},
// };

// static error_t parse_arg(int key, char *arg, struct argp_state *state)
// {
// 	switch (key) {
// 	case 'v':
// 		env.verbose = true;
// 		break;
// 	case 'd':
// 		errno = 0;
// 		env.min_duration_ms = strtol(arg, NULL, 10);
// 		if (errno || env.min_duration_ms <= 0) {
// 			fprintf(stderr, "Invalid duration: %s\n", arg);
// 			argp_usage(state);
// 		}
// 		break;
// 	case ARGP_KEY_ARG:
// 		argp_usage(state);
// 		break;
// 	default:
// 		return ARGP_ERR_UNKNOWN;
// 	}
// 	return 0;
// }

// static const struct argp argp = {
// 	.options = opts,
// 	.parser = parse_arg,
// 	.doc = argp_program_doc,
// };

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
// {
// 	// if (level == LIBBPF_DEBUG && !env.verbose)
// 	// 	return 0;
// 	return vfprintf(stderr, format, args);
// }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct nvme_latency_bpf *skel;
	int err;

	/* Parse command line arguments */
	// err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	// if (err)
	// 	return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = nvme_latency_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	// skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = nvme_latency_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = nvme_latency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	/* Process events */
	while (!exiting) {
		usleep(10);
	}

cleanup:
	/* Clean up */
	nvme_latency_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
