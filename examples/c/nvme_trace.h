/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __NVME_TRACE_H
#define __NVME_TRACE_H

struct nvme_trace_event {
	int action;
	int cid;
};

#endif /* __NVME_TRACE_H */
