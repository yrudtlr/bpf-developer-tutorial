# eBPF Tutorial by Example 7: Capturing Process Execution, Output with perf event array

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구로, 개발자가 사용자 정의 코드를 런타임에 동적으로 로드, 업데이트 및 실행할 수 있습니다.

이 글은 eBPF Tutorial by Example의 7번째 부분으로 주로 리눅스 커널에서 프로세스 실행 이벤트를 캡처하고 perf 이벤트 배열을 통해 사용자 명령줄에 출력하는 방법을 소개합니다. 이를 통해 /sys/kernel/debug/tracing/trace_pipe 파일을 확인하여 eBPF 프로그램의 출력을 볼 필요가 없습니다. perf 이벤트 어레이를 통해 사용자 공간에 정보를 보낸 후 복잡한 데이터 처리 및 분석을 수행할 수 있습니다.

## perf buffer

eBPF는 eBPF 프로그램에서 사용자 공간 제어기로 정보를 전달하기 위한 두 개의 순환 버퍼를 제공합니다. 첫 번째는 적어도 커널 v4.15부터 존재했던 perf 순환 버퍼입니다. 두 번째는 이후에 소개된 BPF 순환 버퍼입니다. 이 글에서는 퍼퍼 순환 버퍼만을 고려합니다.

## execsnoop

perf event array를 통해 사용자 명령줄에 출력물을 출력하려면 헤더 파일과 C 소스 파일을 작성해야 합니다. 예제 코드는 다음과 같습니다:

헤더 파일: execsnoop.h
```c
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16

struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char comm[TASK_COMM_LEN];
};

#endif /* __EXECSNOOP_H */
```

Source file: execsnoop.bpf.c
```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    u64 id;
    pid_t pid, tgid;
    struct event event={0};
    struct task_struct *task;

    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    event.pid = tgid;
    event.uid = uid;
    task = (struct task_struct*)bpf_get_current_task();
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

이 코드는 실행 시스템 호출의 항목을 캡처하기 위한 eBPF 프로그램을 정의합니다.

엔트리 프로그램에서는 먼저 현재 프로세스의 프로세스 ID와 사용자 ID를 얻은 다음 bpf_get_current_task 함수를 사용하여 현재 프로세스의 task_struct 구조를 얻은 다음 bpf_probe_read_str 함수를 사용하여 프로세스 이름을 읽습니다. 마지막으로 bpf_perf_event_output 함수를 사용하여 프로세스 실행 이벤트를 perf 버퍼로 출력합니다.

## Summary

이 글에서는 리눅스 커널에서 실행되는 프로세스의 이벤트를 캡처하여 perf event array를 사용하여 사용자 명령줄로 출력하는 방법을 소개합니다. perf event array를 통해 사용자 공간으로 정보를 보낸 후 복잡한 데이터 처리 및 분석을 수행할 수 있습니다. libbpf의 해당 커널 코드에서 구조와 해당 헤더 파일은 다음과 같이 정의할 수 있습니다:

```c
struct {
 __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
 __uint(key_size, sizeof(u32));
 __uint(value_size, sizeof(u32));
} events SEC(".maps");
```

이를 통해 사용자 공간으로 직접 정보를 보낼 수 있습니다.
