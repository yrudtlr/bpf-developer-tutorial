# eBPF Tutorial by Example 6: Capturing Signal Sending and Store State with Hash Maps

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구로, 개발자가 사용자 정의 코드를 런타임에 동적으로 로드, 업데이트 및 실행할 수 있습니다.

이 기사는 eBPF Tutorial by Example의 여섯 번째 부분입니다. 주로 프로세스에 신호를 보내는 시스템 콜 모음을 캡처하고 해시 맵을 사용하여 상태를 저장하는 eBPF 도구를 구현하는 방법을 소개합니다.

## sigsnoop

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event
{
    unsigned int pid;
    unsigned int tpid;
    int sig;
    int ret;
    char comm[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct event);
} values SEC(".maps");

static int probe_entry(pid_t tpid, int sig)
{
    struct event event = {};
    __u64 pid_tgid;
    __u32 tid;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32)pid_tgid;
    event.pid = pid_tgid >> 32;
    event.tpid = tpid;
    event.sig = sig;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
    return 0;
}

static int probe_exit(void *ctx, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct event *eventp;

    eventp = bpf_map_lookup_elem(&values, &tid);
    if (!eventp)
        return 0;

    eventp->ret = ret;
    bpf_printk("PID %d (%s) sent signal %d ",
               eventp->pid, eventp->comm, eventp->sig);
    bpf_printk("to PID %d, ret = %d",
               eventp->tpid, ret);

cleanup:
    bpf_map_delete_elem(&values, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
    pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
    return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

위 코드는 kill, tkill, tgkill을 포함하여 프로세스에 신호를 보내는 시스템 콜을 캡처하기 위한 eBPF 프로그램을 정의합니다. tracepoint를 사용하여 시스템 콜의 입력 및 종료 이벤트를 캡처하고 이러한 이벤트가 발생하면 probe_entry 및 probe_exit와 같은 지정된 프로브 함수를 실행합니다. 프로브 함수에서는 bpf_map을 사용하여 송신 신호의 프로세스 ID, 수신 신호의 프로세스 ID, 신호 값 및 현재 작업의 실행 파일 이름을 포함하여 캡처된 이벤트 정보를 저장합니다. 시스템 콜이 종료되면 bpf_map에 저장된 이벤트 정보를 검색하고 bpf_printk를 사용하여 시스템 호출의 프로세스 ID, 프로세스 이름, 송신 신호 및 반환 값을 인쇄합니다.

마지막으로 SEC 매크로를 사용하여 프로브를 정의하고 캡처할 시스템 호출의 이름과 실행할 프로브 기능을 지정해야 합니다.

## Summary

이 기사에서는 신호를 사용하여 프로세스에서 보낸 시스템 콜 모음을 캡처하고 해시 맵을 사용하여 상태를 저장하는 eBPF 도구 구현을 소개합니다. 해시 맵을 사용하려면 다음과 같은 구조를 정의해야 합니다:

```c
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, __u32);
 __type(value, struct event);
} values SEC(".maps");
```

그리고 맵에 `bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem` 등 해당 API를 사용해 접근합니다.
