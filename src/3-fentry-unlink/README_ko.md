# eBPF Tutorial by Example 3: Monitoring unlink System Calls with fentry

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구입니다. 개발자가 커널의 런타임에 사용자 정의 코드를 동적으로 로드, 업데이트 및 실행할 수 있도록 해줍니다.

이 기사는 eBPF 튜토리얼의 세 번째 부분으로 eBPF에서 fentry를 사용하여 Unlink 시스템 콜을 캡처하는 데 중점을 둡니다.

## Fentry

fentry(function entry)와 fexit(function exit)는 리눅스 커널 함수의 진입 및 퇴출 지점에서 추적하는 데 사용되는 eBPF(Extended Berkeley Packet Filter)의 두 가지 종류의 프로브입니다. 이들은 개발자들이 커널 함수 실행의 특정 단계에서 정보를 수집하거나 매개 변수를 수정하거나 반환 값을 관찰할 수 있도록 합니다. 이 추적 및 모니터링 기능은 성능 분석, 문제 해결 및 보안 분석 시나리오에서 매우 유용합니다.

**kprobe에 비해 fentry와 fexit 프로그램은 성능과 가용성이 높습니다.** 이 예에서는 일반 C 코드와 마찬가지로 함수의 매개 변수에 대한 포인터를 다른 도움 없이 직접 액세스할 수 있습니다. fexit와 kretprobe 프로그램의 주요 차이점은 fexit 프로그램이 함수의 입력 매개 변수와 반환 값에 모두 액세스할 수 있는 반면, kretprobe 프로그램은 반환 값에만 액세스할 수 있다는 것입니다. **5.5 커널부터 fentry와 fexit는 eBPF 프로그램에서 사용할 수 있습니다.**

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}
```

이 프로그램은 C언어로 작성된 eBPF(Extended Berkeley Packet Filter) 프로그램입니다. BPF fentry 및 fexit 프로브를 사용하여 Linux 커널 함수 do_unlinkat를 추적합니다. 이 튜토리얼에서는 이 프로그램을 예로 들어 eBPF의 fentry를 사용하여 시스템 호출을 탐지하고 캡처하는 방법을 배울 것입니다.

프로그램은 다음과 같은 부분으로 구성됩니다:

1. 헤더 파일 포함: vmlinux.h(커널 데이터 구조에 액세스하기 위한), bpf/bpf_helpers.h(eBPF 도우미 기능 포함), bpf/bpf_tracing.h(eBPF 추적 관련 기능 포함).
2. 라이센스 정의: 여기서 라이센스 정보 "Dual BSD/GPL"을 포함하는 LICENCE라는 이름의 문자 배열이 정의됩니다.
3. fentry 프로브 정의: do_unlinkat 함수의 진입점에서 트리거되는 BPF_PROG(do_unlinkat)라는 이름의 fentry 프로브를 정의합니다. 이 프로브는 현재 프로세스의 PID(Process ID)를 검색하여 커널 로그에 파일명과 함께 인쇄합니다.
4. fexit 프로브 정의: 또한 do_unlinkat 함수의 종료 지점에서 트리거되는 BPF_PROG(do_unlinkat_exit)라는 이름의 fexit 프로브를 정의합니다. fentry 프로브와 마찬가지로 이 프로브도 현재 프로세스의 PID를 검색하여 커널 로그에 파일 이름 및 반환 값과 함께 인쇄합니다.

이 예제를 통해 eBPF의 fentry 및 fexit 프로브를 사용하여 이 튜토리얼의 Unlink system 호출과 같은 커널 함수 호출을 모니터링하고 캡처하는 방법을 배울 수 있습니다.

```sh
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ touch test1
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ rm test1
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ touch test1
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ rm test1
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ touch test2
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ rm test2
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ sudo cat /sys/kernel/debug/tracing/trace_pipe
[sudo] password for ebpf: 
rm-19145   [000] d...1 12976.727113: bpf_trace_printk: fentry: pid = 19145, filename = te
rm-19145   [000] d...1 12976.727190: bpf_trace_printk: fexit: pid = 19145, filename = test1, ret 
rm-19552   [001] d...1 12980.303556: bpf_trace_printk: fentry: pid = 19552, filename = te
rm-19552   [001] d...1 12980.303720: bpf_trace_printk: fexit: pid = 19552, filename = test1, ret 
rm-19971   [000] d...1 12987.567150: bpf_trace_printk: fentry: pid = 19971, filename = te
rm-19971   [000] d...1 12987.567194: bpf_trace_printk: fexit: pid = 19971, filename = test2, ret = 0
```