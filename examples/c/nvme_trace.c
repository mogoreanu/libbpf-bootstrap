#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "nvme_trace.h"
#include "nvme_trace.skel.h"

/*
make nvme_trace
sudo ./nvme_trace
*/

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static void sig_handler(int sig) {
  exiting = true;
}

static int handle_nvme_event(void *ctx, void *data, size_t data_sz)
{
  const struct nvme_trace_event* my_nvme_event = data;

  if (my_nvme_event->action == 0) {
    printf("Starting cid=%d\n", my_nvme_event->cid);
  } else {
    printf("Completing cid=%d\n", my_nvme_event->cid);
  }

  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer* nvme_trace_events = NULL;
  struct nvme_trace_bpf *skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = nvme_trace_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = nvme_trace_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  err = nvme_trace_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  nvme_trace_events = ring_buffer__new(bpf_map__fd(skel->maps.nvme_trace_events), handle_nvme_event, NULL, NULL);
  if (!nvme_trace_events) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  printf("Successfully started!\n");

  while (!exiting) {
    err = ring_buffer__poll(nvme_trace_events, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  /* Clean up */
  ring_buffer__free(nvme_trace_events);
  nvme_trace_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}
