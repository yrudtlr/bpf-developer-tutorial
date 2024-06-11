# eBPF Tutorial by Example 8: Monitoring Process Exit Events, Output with Ring Buffer

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구입니다. 개발자들이 커널의 런타임에 사용자 정의 코드를 동적으로 로드하고 업데이트하고 실행할 수 있도록 해줍니다.

이 기사는 eBPF Tutorial by Example의 여덟 번째 부분으로 eBPF를 사용한 프로세스 종료 이벤트 모니터링에 중점을 둡니다.

## Ring Buffer

이제 eBPF 링 버퍼라는 새로운 BPF 데이터 구조가 있습니다. **현재 커널에서 사용자 공간으로 데이터를 전송하기 위한 사실상의 표준인 BPF perf 버퍼의 메모리 효율성과 이벤트 재정렬 문제를 해결합니다.** perf 버퍼와의 호환성을 제공하여 마이그레이션을 쉽게 하는 동시에 사용성을 향상시킨 새로운 예약/커밋 API를 도입했습니다. **또한 합성 및 실제 벤치마크 테스트를 통해 거의 모든 경우에 BPF 프로그램에서 사용자 공간으로 데이터를 전송하기 위한 기본 선택 사항이 eBPF 링 버퍼여야 한다는 것이 나타났습니다.**

### eBPF Ring Buffer vs eBPF Perf Buffer

BPF 프로그램은 후처리와 로깅을 위해 수집된 데이터를 사용자 공간으로 보내야 할 때마다 일반적으로 BPF perf 버퍼(perfbuf)를 사용합니다. Perfbuf는 커널과 사용자 공간 사이의 효율적인 데이터 교환을 가능하게 하는 CPU별 순환 버퍼 모음입니다. 실제로는 잘 작동하지만 불편함이 입증된 두 가지 주요 단점이 있는데, 비효율적인 메모리 사용과 이벤트 재정렬입니다.

이러한 문제를 해결하기 위해 리눅스 5.8부터 BPF는 BPF ring buffer라는 새로운 BPF 데이터 구조를 도입합니다. 여러 CPU에 걸쳐 안전하게 공유할 수 있는 MPSC(Multiple Producer, Single Consumer) 큐입니다.

BPF 링 버퍼는 BPF perf buffer와 유사한 기능들을 지원합니다:

- 가변 길이 데이터 레코드
- 추가 메모리 복사본 및/또는 커널 시스템 호출 입력 없이 메모리 매핑된 영역을 통해 사용자 공간에서 데이터를 효율적으로 읽을 수 있습니다.
- 절대적인 최소 지연 시간으로 epoll 알림 및 비지 루프 작업을 지원합니다.

동시에 BPF 링 버퍼는 BPF perf 버퍼의 다음과 같은 문제를 해결합니다:

- 메모리 오버헤드
- Data ordering
- 불필요한 작업과 추가적인 데이터 복사

## exitsnoop

이 기사는 eBPF Tutorial by Example의 여덟 번째 부분으로 eBPF를 사용하여 프로세스 종료 이벤트를 모니터링하고 링 버퍼를 사용하여 사용자 공간에 출력하는 데 중점을 둡니다.

링 버퍼를 사용하여 출력된 것을 사용자 공간에 출력하는 단계는 perf 버퍼와 유사합니다. 먼저 헤더 파일을 정의해야 합니다:

Header File: exitsnoop.h
```c
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
};

#endif /* __BOOTSTRAP_H */
```

Source File: exitsnoop.bpf.c
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, start_time = 0;
    
    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);

    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

이 코드는 exitsnoop을 사용하여 프로세스 종료 이벤트를 모니터링하고 링 버퍼를 사용하여 사용자 공간에 출력을 인쇄하는 방법을 보여줍니다:

1. 먼저 필요한 헤더와 exitnoop.h를 포함합니다.
2. eBPF 프로그램의 라이센스 요구 사항인 "Dual BSD/GPL" 내용으로 "LICENCE"라는 글로벌 변수를 정의합니다.
3. 우리는 커널 공간에서 사용자 공간으로 데이터를 전송하는 데 사용될 BPF_MAP_TYPE_RINGBUF 유형의 `rb` 매핑을 정의합니다. 우리는 256 * 1024로 링 버퍼의 최대 용량을 나타내는 `max_entries`를 지정합니다.
4. 프로세스 종료 이벤트가 트리거될 때 실행되는 handle_exit라는 이름의 eBPF 프로그램을 정의합니다. 이 프로그램은 `ctx`라는 이름의 trace_event_raw_sched_process_template struct pointer를 파라미터로 사용합니다.
5. 현재 작업의 PID와 TID를 얻기 위해 bpf_get_current_pid_tgid() 함수를 사용합니다. 기본 스레드의 경우 PID와 TID가 같고 하위 스레드의 경우 다릅니다. 프로세스(기본 스레드)의 종료에만 관심이 있기 때문에 하위 스레드의 종료 이벤트는 무시하고 PID와 TID가 다르면 0을 반환합니다.
6. 우리는 bpf_ringbuf_reserve 함수를 사용하여 링 버퍼의 이벤트 구조에 대한 공간을 예약합니다. 예약이 실패하면 0을 반환합니다.
7. bpf_get_current_task() 함수를 사용하여 현재 작업에 대한 task_struct 구조 포인터를 얻습니다.
8. 프로세스 기간, PID, PPID, 종료 코드, 프로세스 이름 등 프로세스 관련 정보를 예약된 이벤트 구조체에 입력합니다.
9. 마지막으로 bpf_ringbuf_submit 함수를 사용하여 채워진 이벤트 구조를 링 버퍼에 제출하여 사용자 공간에서 추가 처리 및 출력을 수행합니다.

이 예제는 eBPF 프로그램에서 exitsnoop과 ring buffer를 사용하여 프로세스 종료 이벤트를 캡처하고 관련 정보를 사용자 공간으로 전달하는 방법을 보여줍니다. 이는 프로세스 종료 이유를 분석하고 시스템 동작을 모니터링하는 데 유용합니다.

## Compile and Run

## Summary

이 글에서는 리눅스 시스템에서 프로세스 종료 이벤트를 모니터링하고 캡처된 이벤트를 링 버퍼를 통해 사용자 공간 프로그램으로 보낼 수 있는 eunomia-bpf를 사용하여 간단한 BPF 프로그램을 개발하는 방법을 소개합니다. 이 글에서는 eunomia-bpf를 사용하여 이 예제를 컴파일하고 실행했습니다.
