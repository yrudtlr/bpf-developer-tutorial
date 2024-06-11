# eBPF Tutorial by Example 4: Capturing Opening Files and Filter with Global Variables

eBPF(Extended Berkeley Packet Filter)는 커널에서 사용자가 안전하고 효율적인 프로그램을 실행할 수 있도록 하는 커널 실행 환경입니다. 네트워크 필터링, 성능 분석, 보안 모니터링 및 기타 시나리오에 일반적으로 사용됩니다. eBPF의 힘은 커널에서 런타임에 네트워크 패킷이나 시스템 호출을 캡처하고 수정하여 운영 체제의 동작을 모니터링하고 조정할 수 있는 능력에 있습니다.

이 기사는 eBPF 튜토리얼의 네 번째 부분으로, 주로 eBPF의 글로벌 변수를 사용하여 프로세스 열기 파일의 시스템 호출 모음을 캡처하고 프로세스 PID를 필터링하는 방법에 중점을 둡니다.

리눅스 시스템에서 프로세스와 파일 사이의 상호 작용은 시스템 호출을 통해 이루어집니다. 시스템 호출은 사용자 공간 프로그램과 커널 공간 프로그램 사이의 인터페이스 역할을 하여 사용자 프로그램이 커널에 특정 작업을 요청할 수 있도록 합니다. 이 튜토리얼에서는 파일을 여는 데 사용되는 sys_openat 시스템 호출에 중점을 둡니다.

프로세스가 파일을 열면 커널에 sys_openat 시스템 호출을 발행하고 관련 파라미터(파일 경로, 오픈 모드 등)를 전달합니다. 커널은 이 요청을 처리하고 파일 디스크립터를 반환하며, 이는 이후의 파일 작업에 참조 역할을 합니다. sys_openat 시스템 호출을 캡처하여 프로세스가 파일을 여는 시기와 방법을 이해할 수 있습니다.

## Capturing the System Call Collection of Process Opening Files in eBPF

먼저 파일을 여는 프로세스의 시스템 콜을 캡처하기 위해 eBPF 프로그램을 작성해야 합니다. 구체적인 구현은 다음과 같습니다:

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @description "Process ID to trace"
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;

    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";
```

이 eBPF 프로그램은 다음을 구현합니다:

1. 헤더 파일 포함: <vmlinux.h>는 커널 데이터 구조의 정의를 포함하고, <bpf/bpf_helpers.h>는 eBPF 프로그램에서 필요한 도우미 기능을 포함합니다.
2. 지정된 프로세스 ID를 필터링하기 위한 전역 변수 pid_target을 정의합니다. 0으로 설정하면 모든 프로세스에서 sys_openat이 호출됩니다.
3. SEC 매크로를 사용하여 추적 지점 "tracepoint/syscalls/sys_enter_openat"과 관련된 eBPF 프로그램을 정의합니다. 이 추적 지점은 프로세스가 sys_openat 시스템 호출을 시작할 때 트리거됩니다.
4. eBPF 프로그램 tracepoint__syscalls_sys_enter_openat를 구현합니다. 이 구조에는 시스템 호출에 대한 정보가 포함되어 있습니다.
5. 현재 프로세스의 PID 및 TID(Thread ID)를 검색하려면 bpf_get_current_pid_tgid() 함수를 사용합니다. PID에만 관심이 있기 때문에 32비트 값을 오른쪽으로 이동하여 type u32의 변수 pid에 할당합니다.
6. pid_target 변수가 현재 프로세스의 PID와 동일한지 확인합니다. pid_target이 0이 아니고 현재 프로세스의 PID와 동일하지 않으면 false를 반환하여 해당 프로세스의 호출 시 sys_open을 캡처하지 않습니다.
7. bpf_printk() 함수를 사용하여 캡처된 프로세스 ID와 통화 시 sys_open에 대한 관련 정보를 인쇄합니다. 이러한 정보는 BPF 도구를 사용하여 사용자 공간에서 볼 수 있습니다.
8. 프로그램 라이센스를 eBPF 프로그램을 실행하기 위한 필수 조건인 "GPL"로 설정합니다.

이 프로그램을 실행한 후에는 /sys/kernel/debug/trace/trace_pipe 파일을 보고 eBPF 프로그램의 출력을 볼 수 있습니다:

```sh
ps-21111   [000] d...1 13700.415345: bpf_trace_printk: Process ID: 21111 enter sys openat
ps-21111   [000] d...1 13700.415368: bpf_trace_printk: Process ID: 21111 enter sys openat
ps-21111   [000] d...1 13700.415381: bpf_trace_printk: Process ID: 21111 enter sys openat
ps-21111   [000] d...1 13700.415389: bpf_trace_printk: Process ID: 21111 enter sys openat
ps-21111   [000] d...1 13700.415398: bpf_trace_printk: Process ID: 21111 enter sys openat
ps-21111   [000] d...1 13700.415408: bpf_trace_printk: Process ID: 21111 enter sys openat
```

## Filtering Process PID in eBPF using Global Variables

**전역 변수는 eBPF 프로그램에서 데이터 공유 메커니즘으로 작용하여 사용자 공간 프로그램과 eBPF 프로그램 간의 데이터 상호 작용을 허용합니다.** 이는 특정 조건을 필터링하거나 eBPF 프로그램의 동작을 수정할 때 매우 유용합니다. 이러한 설계를 통해 사용자 공간 프로그램이 실행 시간에 eBPF 프로그램의 동작을 동적으로 제어할 수 있습니다.

이 예제에서 전역 변수 pid_target은 프로세스 PID를 필터링하는 데 사용됩니다. 사용자 공간 프로그램은 eBPF 프로그램에서 지정된 PID와 관련된 sys_openat 시스템 호출만 캡처하도록 이 변수의 값을 설정할 수 있습니다.

전역 변수를 사용하는 원리는 eBPF 프로그램의 데이터 섹션에 정의되고 저장된다는 것입니다. eBPF 프로그램이 커널에 로드되어 실행되면 이러한 전역 변수는 커널에 유지되고 BPF 시스템 콜을 통해 액세스할 수 있습니다. **사용자 공간 프로그램은 bpf_obj_get_info_by_fd 및 bpf_obj_get_info와 같은 BPF 시스템 콜의 특정 기능을 사용하여 전역 변수의 위치 및 값을 포함한 eBPF 개체에 대한 정보를 얻을 수 있습니다.**

캡처할 프로세스의 PID는 다음과 같이 --pid_target 옵션을 사용하여 지정할 수 있습니다:

```sh
root@ebpf:/home/ebpf/workspace/bpf-developer-tutorial-source# ecli run opensnoop/package.json --pid_target 1499
```

이 프로그램을 실행한 후에는 /sys/kernel/debug/trace/trace_pipe 파일을 보고 eBPF 프로그램의 출력을 볼 수 있습니다:

```sh
node-1499    [001] d...1 14450.341365: bpf_trace_printk: Process ID: 1499 enter sys openat
node-1499    [001] d...1 14450.352908: bpf_trace_printk: Process ID: 1499 enter sys openat
node-1499    [001] d...1 14450.353132: bpf_trace_printk: Process ID: 1499 enter sys openat
node-1499    [001] d...1 14450.542129: bpf_trace_printk: Process ID: 1499 enter sys openat
node-1499    [001] d...1 14450.553942: bpf_trace_printk: Process ID: 1499 enter sys openat
node-1499    [001] d...1 14450.554256: bpf_trace_printk: Process ID: 1499 enter sys openat
```

## Summary

이 기사에서는 eBPF 프로그램을 사용하여 프로세스 파일 열기에 대한 시스템 호출을 캡처하는 방법을 소개합니다. eBPF 프로그램에서 우리는 `tracepoint__syscalls_enter_open` 및 `tracepoint__sys_enter_openat` 함수를 정의하고 SEC 매크로를 사용하여 추적점 sys_enter_open 및 sys_enter_openat에 연결하여 프로세스 파일 열기에 대한 시스템 호출을 캡처할 수 있습니다. `bpf_get_current_pid_tgid` 함수를 사용하여 open 또는 openat 시스템 콜을 호출하는 프로세스 ID를 가져오고 bpf_printk 함수를 사용하여 커널 로그에 출력할 수 있습니다. eBPF 프로그램에서 글로벌 변수 pid_target을 정의하여 캡처할 프로세스의 pid를 지정하고 지정된 프로세스의 정보만 출력하여 출력을 필터링할 수도 있습니다.

이 자습서를 학습함으로써 eBPF의 특정 프로세스에 대한 시스템 호출을 캡처하고 필터링하는 방법을 더 깊이 이해해야 합니다. 이 방법은 시스템 모니터링, 성능 분석 및 보안 감사에 널리 적용됩니다.