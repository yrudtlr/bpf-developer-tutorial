# eBPF Tutorial by Example 11: Develop User-Space Programs with libbpf and Trace exec() and exit()

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구입니다. 커널 런타임 동안 개발자가 동적으로 사용자 정의 코드를 로드하고 업데이트하고 실행할 수 있도록 해줍니다.

이 튜토리얼에서는 커널 공간과 사용자 공간 eBPF 프로그램이 어떻게 함께 작동하는지 배울 것입니다. 또한 네이티브 libbpf를 사용하여 사용자 공간 프로그램을 개발하고 eBPF 응용 프로그램을 실행 파일로 패키징하여 여러 커널 버전에 배포하는 방법도 배울 것입니다.

## The libbpf Library and Why We Need to Use It

libbpf는 eBPF 프로그램을 로드하고 실행하는 것을 돕기 위해 커널 버전과 함께 배포되는 C언어 라이브러리입니다. eBPF 시스템과 상호 작용하기 위한 C API 세트를 제공하므로 개발자가 eBPF 프로그램을 로드하고 관리하기 위해 사용자 공간 프로그램을 더 쉽게 작성할 수 있습니다. 이러한 사용자 공간 프로그램은 일반적으로 시스템 성능 분석, 모니터링 또는 최적화에 사용됩니다.

libbpf 라이브러리를 사용하면 다음과 같은 몇 가지 장점이 있습니다:

- eBPF 프로그램의 로딩, 업데이트 및 실행 과정을 간소화합니다.
- 사용하기 쉬운 API 세트를 제공하여 개발자가 낮은 수준의 세부 사항을 처리하는 대신 핵심 로직 작성에 집중할 수 있습니다.
- 커널의 eBPF 서브시스템과 호환성을 보장하여 유지보수 비용을 절감합니다.

동시에 libbpf와 BTF(BPF Type Format)는 eBPF 생태계의 중요한 구성 요소입니다. 이들은 서로 다른 커널 버전 간의 호환성을 달성하는 데 중요한 역할을 합니다. BTF는 eBPF 프로그램의 유형 정보를 설명하는 데 사용되는 메타데이터 형식입니다. BTF의 주요 목적은 eBPF 프로그램이 더 쉽게 접근하고 조작할 수 있도록 커널의 데이터 구조를 설명하는 구조화된 방법을 제공하는 것입니다.

다양한 커널 버전 간의 호환성을 달성하기 위한 BTF의 주요 역할은 다음과 같습니다:

- BTF를 사용하면 eBPF 프로그램이 특정 커널 버전을 하드코딩하지 않고도 커널 데이터 구조의 상세한 유형 정보에 액세스할 수 있습니다. 이를 통해 eBPF 프로그램이 서로 다른 커널 버전에 적응하여 커널 버전 간에 호환성을 달성할 수 있습니다.
- BPF CO-RE(Compile Once, Run Everywhere) 기술을 사용하여, eBPF 프로그램은 BTF를 활용하여 컴파일 중에 커널 데이터 구조의 유형 정보를 파싱합니다. 따라서, 다양한 커널 버전에서 실행할 수 있는 eBPF 프로그램을 생성할 수 있습니다.

libbpf와 BTF를 결합하여 eBPF 프로그램은 커널 버전별로 별도의 컴파일 없이 다양한 커널 버전에서 구동이 가능합니다. 이를 통해 eBPF 생태계의 휴대성과 호환성이 크게 향상되고 개발 및 유지보수의 어려움이 줄어듭니다.

## What is Bootstrap

부트스트랩은 libbpf를 활용하는 완전한 응용 프로그램입니다. eBPF 프로그램을 사용하여 커널("tp/sched/sched_process_exec")의 exec() 시스템 콜을 추적하며, 이는 주로 새로운 프로세스(fork() 부분을 제외한) 생성에 해당합니다. 또한, 각 프로세스가 종료되는 시점을 파악하기 위해 ("tp/sched/sched_process_exit") 프로세스의 exit() 시스템 콜을 추적합니다.

이 두 BPF 프로그램은 바이너리 파일 이름과 같은 새로운 프로세스에 대한 흥미로운 정보를 캡처하고 프로세스의 수명 주기를 측정하기 위해 함께 작동합니다. 그들은 프로세스가 종료될 때 종료 코드 또는 리소스 소비와 같은 흥미로운 통계도 수집합니다. 이것은 커널의 내부 작동에 대해 더 깊은 이해를 얻고 실제로 어떻게 작동하는지 관찰할 수 있는 좋은 시작점입니다.

부트스트랩은 또한 명령줄 인수 구문 분석에 argp API(libc의 일부)를 사용하여 사용자가 명령줄 옵션을 통해 응용 프로그램의 동작을 구성할 수 있습니다. 이를 통해 유연성을 제공하고 사용자가 특정 필요에 따라 프로그램 동작을 지정할 수 있도록 합니다. 이러한 기능은 eunomia-bpf 도구를 사용하여 달성할 수도 있지만 여기서 libbpf를 사용하면 추가 복잡성을 감수하면서 사용자 공간에서 더 높은 확장성을 제공합니다.

## Bootstrap

부트스트랩은 커널공간과 사용자공간 두 부분으로 구성되어 있습니다. 커널공간 부분은 eBPF 프로그램으로 exec()과 exit() 시스템 콜을 추적합니다. 사용자공간 부분은 c언어 프로그램으로 libbpf 라이브러리를 이용하여 커널공간 프로그램을 로드하여 실행하고 커널공간 프로그램에서 수집된 데이터를 처리합니다.

### Kernel-space eBPF Program bootstrap.bpf.c
```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // map type
    __uint(max_entries, 8192);          // max length
    __type(key, pid_t);                 // key type
    __type(value, u64);                 // value type
} exec_start SEC(".maps");              // map name

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // map type
    __uint(max_entries, 256 * 1024);    // map length
} rb SEC(".maps");                      // map name

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    unsigned fname_off;
    struct event *e;
    pid_t pid;
    u64 ts;

    /* remember time exec() was executed for this PID */
    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    /* don't emit exec events when minimum duration is specified */
    if (min_duration_ns)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    /* successfully submit it to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, duration_ns = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* if we recorded start of the process, calculate lifetime duration */
    start_ts = bpf_map_lookup_elem(&exec_start, &pid);
    if (start_ts)duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;
    bpf_map_delete_elem(&exec_start, &pid);

    /* if process didn't live long enough, return early */
    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration_ns = duration_ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

이 코드는 exec() 및 exit() 시스템 콜을 추적하는 데 사용되는 커널 수준의 eBPF 프로그램(bootstrap.bpf.c)입니다. eBPF 프로그램을 사용하여 프로세스 생성 및 종료 이벤트를 캡처하고 관련 정보를 사용자 공간 프로그램으로 보내 처리합니다. 아래는 코드에 대한 자세한 설명입니다.

먼저 필요한 헤더를 포함하고 eBPF 프로그램에 대한 라이센스를 정의합니다. 또한 `exec_start`와 `rb` 두 가지 eBPF 맵을 정의합니다. `exec_start`는 프로세스가 실행되기 시작할 때 타임스탬프를 저장하는 데 사용되는 해시 유형 eBPF 맵입니다. `rb`는 캡처된 이벤트 데이터를 저장하고 사용자 공간 프로그램으로 보내는 데 사용되는 링 버퍼 유형 eBPF 맵입니다.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

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
```

다음으로 프로세스가 exec() 시스템 콜을 실행할 때 트리거되는 handle_exec이라는 이름의 eBPF 프로그램을 정의합니다. 먼저 현재 프로세스에서 PID를 검색하고 프로세스가 실행을 시작할 때 타임스탬프를 기록하여 `exec_start` 맵에 저장합니다.

```c
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    // ...
    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    // ...
}
```

그런 다음 원형 버퍼 맵 `rb`에서 이벤트 구조를 예약하고 프로세스 ID, 부모 프로세스 ID, 프로세스 이름과 같은 관련 데이터를 채웁니다. 그런 다음 이 데이터를 사용자 모드 프로그램으로 보내 처리합니다.

```c
    // reserve sample from BPF ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // fill out the sample with data
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // successfully submit it to user-space for post-processing
    bpf_ringbuf_submit(e, 0);
    return 0;
```

마지막으로 프로세스가 exit() 시스템 콜을 실행할 때 트리거되는 handle_exit라는 이름의 eBPF 프로그램을 정의합니다. 먼저 현재 프로세스에서 PID와 TID(thread ID)를 검색합니다. PID와 TID가 동일하지 않으면 스레드 exit임을 의미하며 이 이벤트를 무시합니다.

```c
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    // ...
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    // ...
}
```

다음으로 `exec_start` 맵에 저장된 프로세스 실행을 시작한 시간의 타임스탬프를 찾습니다. 타임스탬프가 발견되면 프로세스의 수명 기간을 계산한 다음 `exec_start` 맵에서 레코드를 제거합니다. 타임스탬프가 발견되지 않고 최소 기간이 지정된 경우 직접 반환합니다.

```c
    // if we recorded start of the process, calculate lifetime duration
    start_ts = bpf_map_lookup_elem(&exec_start, &pid);
    if (start_ts)
        duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;
    bpf_map_delete_elem(&exec_start, &pid);

    // if process didn't live long enough, return early
    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;
```

그런 다음 원형 버퍼 맵 `rb`에서 이벤트 structure를 예약하고 프로세스 ID, 부모 프로세스 ID, 프로세스 이름 및 프로세스 지속 시간과 같은 관련 데이터를 채웁니다. 마지막으로 이 데이터를 사용자 모드 프로그램으로 보내 처리합니다.

```c
    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration_ns = duration_ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

이러한 방식으로 프로세스가 exec() 또는 exit() 시스템 콜을 실행하면 eBPF 프로그램은 해당 이벤트를 캡처하여 사용자 공간 프로그램에 자세한 정보를 보내 추가 처리를 수행합니다. 이를 통해 프로세스 생성 및 종료를 쉽게 모니터링하고 프로세스에 대한 자세한 정보를 얻을 수 있습니다.

또한 bootstrap.h 파일에서는 사용자 공간과의 상호 작용을 위한 데이터 구조도 정의합니다:

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    bool exit_event;
};

#endif /* __BOOTSTRAP_H */
```

### User space, bootstrap.c
```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->exit_event) {
		printf("%-8s %-5s %-16s %-7d %-7d [%u]",
		       ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else {
		printf("%-8s %-5s %-16s %-7d %-7d %s\n",
		       ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
```

이 사용자 수준의 프로그램은 주로 eBPF 프로그램을 로드, 검증, 첨부하고 eBPF 프로그램에서 수집한 이벤트 데이터를 받아 출력하는 데 사용되며, 몇 가지 핵심 부분을 분석할 것입니다.

먼저 명령줄 인수를 저장할 env 구조를 정의합니다:
```c
static struct env {
    bool verbose;
    long min_duration_ms;
} env;
```

다음으로 argp 라이브러리를 사용하여 명령줄 인수를 구문 분석합니다:
```c
static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    // ...
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};
```

main() 함수에서는 먼저 명령줄 인수를 구문 분석한 다음, 필요할 때 debug 정보를 출력하도록 libppf_print_fn 인쇄 콜백 함수를 설정합니다:

```c
err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
if (err)
    return err;
libbpf_set_print(libbpf_print_fn);
```

다음으로 eBPF skeleton 파일을 열고 최소 지속 시간 매개 변수를 eBPF 프로그램에 전달한 다음 eBPF 프로그램을 로드하고 첨부합니다:

```c
skel = bootstrap_bpf__open();
if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
}

skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

err = bootstrap_bpf__load(skel);
if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
}

err = bootstrap_bpf__attach(skel);
if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
}
```

그런 다음 eBPF 프로그램에서 보내는 이벤트 데이터를 수신할 링 버퍼를 만듭니다:

```c
rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
}
```

handle_event() 함수는 eBPF 프로그램으로부터 수신한 이벤트를 처리합니다. 이벤트 유형(프로세스 실행 또는 종료)에 따라 타임스탬프, 프로세스 이름, 프로세스 ID, 상위 프로세스 ID, 파일 이름 또는 종료 코드 등의 이벤트 정보를 추출하여 출력합니다.

마지막으로 ring_buffer__poll() 함수를 사용하여 링 버퍼를 폴링하고 수신된 이벤트 데이터를 처리합니다:

```c
while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    // ...
}
```

프로그램이 SIGINT 또는 SIGTERM 신호를 수신하면 최종 정리 및 종료 작업을 완료하고 eBPF 프로그램을 닫고 해제합니다:

```c
cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    bootstrap_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
```

## Dependency Installation

예제를 구축하려면 clang, libelf 및 zlib이 필요합니다. 패키지 이름은 다른 배포판에서 다를 수 있습니다.

Ubuntu/Debian에서 다음 명령을 실행해야 합니다:

```sh
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

CentOS/Fedora에서 다음 명령을 실행해야 합니다:

```sh
sudo dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## Compile and Run

Compile and run the above code:

```sh
ebpf@ebpf:~/workspace/bpf-developer-tutorial/src/11-bootstrap$ git submodule update --init --recursive
Submodule 'src/third_party/blazesym' (https://github.com/libbpf/blazesym) registered for path '../third_party/blazesym'
Submodule 'src/third_party/bpftool' (https://github.com/libbpf/bpftool) registered for path '../third_party/bpftool'
Submodule 'src/third_party/libbpf' (https://github.com/libbpf/libbpf.git) registered for path '../third_party/libbpf'
Cloning into '/home/ebpf/workspace/bpf-developer-tutorial/src/third_party/blazesym'...
Cloning into '/home/ebpf/workspace/bpf-developer-tutorial/src/third_party/bpftool'...
Cloning into '/home/ebpf/workspace/bpf-developer-tutorial/src/third_party/libbpf'...
Submodule path '../third_party/blazesym': checked out 'c57e6d623b88340d500e2ab0b2700ec9e9d4f398'
Submodule path '../third_party/bpftool': checked out '88156afd0fb486fe1a54cefe0dd3b0b744fcec61'
Submodule 'libbpf' (https://github.com/libbpf/libbpf.git) registered for path '../third_party/bpftool/libbpf'
Cloning into '/home/ebpf/workspace/bpf-developer-tutorial/src/third_party/bpftool/libbpf'...
Submodule path '../third_party/bpftool/libbpf': checked out '05f94ddbb837f5f4b3161e341eed21be307eaa04'
Submodule path '../third_party/libbpf': checked out '56069cda7897afdd0ae2478825845c7a7308c878'
ebpf@ebpf:~/workspace/bpf-developer-tutorial/src/11-bootstrap$ 
ebpf@ebpf:~/workspace/bpf-developer-tutorial/src/11-bootstrap$ 
ebpf@ebpf:~/workspace/bpf-developer-tutorial/src/11-bootstrap$ ls
bootstrap.bpf.c  bootstrap.c  bootstrap.h  Makefile  README_en.md  README_ko.md  README.md
ebpf@ebpf:~/workspace/bpf-developer-tutorial/src/11-bootstrap$ make clean
  CLEAN    
ebpf@ebpf:~/workspace/bpf-developer-tutorial/src/11-bootstrap$ make
  MKDIR    .output
  MKDIR    .output/libbpf
  LIB      libbpf.a
  MKDIR    /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/bpf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/btf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/libbpf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/libbpf_errno.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/netlink.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/nlattr.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/str_error.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/libbpf_probes.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/bpf_prog_linfo.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/btf_dump.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/hashmap.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/ringbuf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/strset.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/linker.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/gen_loader.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/relo_core.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/usdt.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/zip.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/staticobjs/elf.o
  AR       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/libbpf.a
  INSTALL  bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h skel_internal.h libbpf_version.h usdt.bpf.h
  INSTALL  /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/libbpf.pc
  INSTALL  /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output//libbpf/libbpf.a 
  MKDIR    bpftool
  BPFTOOL  bpftool/bootstrap/bpftool
...                        libbfd: [ on  ]
...               clang-bpf-co-re: [ on  ]
...                          llvm: [ on  ]
...                        libcap: [ OFF ]
  MKDIR    /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/include/bpf
  INSTALL  /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/include/bpf/hashmap.h
  INSTALL  /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/include/bpf/relo_core.h
  INSTALL  /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/include/bpf/libbpf_internal.h
  MKDIR    /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/
  MKDIR    /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/
  MKDIR    /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/bpf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/btf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf_errno.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/netlink.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/nlattr.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/str_error.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf_probes.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/bpf_prog_linfo.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/btf_dump.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/hashmap.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/ringbuf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/strset.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/linker.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/gen_loader.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/relo_core.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/usdt.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/staticobjs/zip.o
  AR       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/libbpf/libbpf.a
  INSTALL  bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h skel_internal.h libbpf_version.h usdt.bpf.h
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/main.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/common.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/json_writer.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/gen.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/btf.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/xlated_dumper.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/btf_dumper.o
  CC       /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/disasm.o
  LINK     /home/ebpf/workspace/bpf-developer-tutorial/src/11-bootstrap/.output/bpftool/bootstrap/bpftool
  BPF      .output/bootstrap.bpf.o
  GEN-SKEL .output/bootstrap.skel.h
  CC       .output/bootstrap.o
  BINARY   bootstrap
ebpf@ebpf:~/workspace/bpf-developer-tutorial/src/11-bootstrap$ sudo ./bootstrap 
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
07:50:11 EXIT  sleep            54162   54159   [0]
07:50:11 EXEC  sed              54183   54159   /usr/bin/sed
07:50:11 EXIT  sed              54183   54159   [0] (1ms)
07:50:11 EXEC  cat              54184   54159   /usr/bin/cat
07:50:11 EXIT  cat              54184   54159   [0] (0ms)
07:50:11 EXIT  cpuUsage.sh      54185   54159   [0]
07:50:11 EXIT  cpuUsage.sh      54159   54158   [0]
07:50:11 EXIT  sh               54158   1499    [0]
07:50:12 EXEC  sh               54186   1499    /bin/sh
07:50:12 EXEC  which            54187   54186   /usr/bin/which
07:50:12 EXIT  which            54187   54186   [0] (0ms)
07:50:12 EXIT  sh               54186   1499    [0] (1ms)
07:50:12 EXEC  sh               54188   1499    /bin/sh
07:50:12 EXEC  ps               54189   54188   /usr/bin/ps
07:50:12 EXIT  ps               54189   54188   [0] (8ms)
07:50:12 EXIT  sh               54188   1499    [0] (9ms)
07:50:12 EXEC  sh               54190   1499    /bin/sh
07:50:12 EXEC  cpuUsage.sh      54191   54190   /home/ebpf/.vscode-server/cli/servers/Stable-89de5a8d4d6205e5b11647eb6a74844ca23d2573/server/out/vs/base/node/cpuUsage.sh
07:50:12 EXEC  sed              54192   54191   /usr/bin/sed
07:50:12 EXIT  sed              54192   54191   [0] (1ms)
```

## Summary

이 예제를 통해 eBPF 프로그램과 사용자 공간 프로그램을 결합하는 방법을 배웠습니다. 이 조합은 개발자들에게 커널과 사용자 공간 전반에 걸쳐 효율적인 데이터 수집 및 처리를 위한 강력한 툴킷을 제공합니다. eBPF와 libpf를 사용하면 보다 효율적이고 확장 가능하며 안전한 모니터링 및 성능 분석 도구를 구축할 수 있습니다.

다음 튜토리얼에서는 eBPF의 고급 기능을 계속 탐구하고 eBPF 개발 관행에 대해 더 많이 공유할 것입니다. 지속적인 학습과 연습을 통해 eBPF 기술에 대한 더 나은 이해와 숙달을 갖게 되고 실제 문제를 해결하는 데 적용할 수 있습니다.




