# eBPF Tutorial by Example 2: Monitoring unlink System Calls with kprobe

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구입니다. 이를 통해 개발자가 런타임에 사용자 정의 코드를 동적으로 로드하고 업데이트하고 실행할 수 있습니다.

이 글은 eBPF 튜토리얼의 두 번째 부분으로, eBPF에서 언링크 시스템 호출을 캡처하기 위해 kprobe를 사용하는 것에 초점을 맞추고 있습니다. 이 글은 먼저 kprobe의 기본 개념과 기술적 배경을 설명한 다음, eBPF에서 언링크 시스템 호출을 캡처하기 위해 kprobe를 사용하는 방법을 소개할 것입니다.

## Background of kprobes Technology

커널이나 모듈의 디버깅 과정에서 개발자가 특정 함수가 호출되는지, 호출될 때, 실행이 정확한지, 함수의 입력값과 반환값이 무엇인지 알아야 하는 경우가 많습니다. 간단한 접근 방식은 커널 코드의 해당 함수에 로그 인쇄 정보를 추가하는 것입니다. 그러나 이 접근 방식은 종종 커널이나 모듈을 다시 컴파일하고 장치를 다시 시작하는 등의 작업을 필요로 하는데, 이는 복잡하고 원래 코드 실행 프로세스를 방해할 수 있습니다.

kprobe 기술을 사용하여 사용자는 자신의 콜백 함수를 정의하고 커널 또는 모듈의 거의 모든 함수에 동적으로 프로브를 삽입할 수 있습니다(예를 들어 kprobe 자신의 구현 함수와 같이 일부 함수는 프로브할 수 없음). 커널 실행 흐름이 지정된 프로브 함수에 도달하면 콜백 함수를 호출하여 사용자가 원하는 정보를 수집할 수 있습니다. 그러면 커널은 일반 실행 흐름으로 돌아갑니다. 사용자가 충분한 정보를 수집하고 더 이상 프로브를 계속할 필요가 없으면 프로브를 동적으로 제거할 수 있습니다. 따라서 kprobe 기술은 커널 실행 흐름에 미치는 영향을 최소화하고 쉽게 작동할 수 있는 장점이 있습니다.

kprobe 기술은 kprobe, jprobe, kretprobe의 세 가지 검출 방법을 포함합니다. 먼저 kprobe는 가장 기본적인 검출 방법이며 나머지 두 가지의 기본이 됩니다. (함수 내 포함) 모든 위치에 프로브를 배치할 수 있습니다. 프로브를 위한 세 가지 콜백 모드를 제공합니다. pre_handler 함수는 probed 명령이 실행되기 전에 호출되고, post_handler는 probed 명령이 완료된 후에 호출되며(probe 함수가 아님을 유의하십시오), fault_handler는 메모리 액세스 오류가 발생하면 호출됩니다. jprobe는 kprobe를 기반으로 하며 probe 함수의 입력 값을 얻는 데 사용됩니다. 마지막으로 이름에서 알 수 있듯이 kretprobe도 kprobe를 기반으로 하며 probe 함수의 반환 값을 얻는 데 사용됩니다.

**kprobe 기술은 소프트웨어를 통해 구현될 뿐만 아니라 하드웨어 아키텍처의 지원도 필요합니다.** 여기에는 CPU 예외 처리 및 단일 단계 디버깅 기술이 포함됩니다. 전자는 프로그램의 실행 흐름을 사용자 등록 콜백 함수에 입력하도록 하는 데 사용되고, 후자는 프로빙된 명령어를 단일 단계 실행하는 데 사용됩니다. 따라서 모든 아키텍처가 kprobe를 지원하는 것은 아닙니다. 현재 kprobe 기술은 i386, x86_64, ppc64, ia64, sparc64, arm, ppc 및 Mips를 포함한 다양한 아키텍처를 지원합니다(일부 아키텍처 구현이 완료되지 않을 수 있음에 유의하십시오. 자세한 내용은 커널의 Documentation/kprobe.txt 참조).

### k프로브의 기능 및 사용 제한

1. kprobe를 사용하면 여러 kprobe를 동일한 프로브 위치에 등록할 수 있지만 현재 jprobe는 이를 지원하지 않습니다. 또한 다른 jprobe 콜백 함수나 kprobe의 post_handler 콜백 함수를 프로브 포인트로 사용할 수 없습니다.

2. 일반적으로 인터럽트 핸들러를 포함하여 커널의 모든 기능을 탐색할 수 있습니다. 그러나 kernel/kprobe.c 및 arch/*/kernel/kprobe.c에서 kprobe 자체를 구현하는 데 사용되는 기능은 탐색할 수 없습니다. 또한 do_page_fault 및 notifier_call_chain도 허용되지 않습니다.

3. 인라인 함수가 프로브 포인트로 사용되는 경우, kprobe는 해당 함수의 모든 인스턴스에 대해 프로브 포인트가 등록되는 것을 보장하지 못할 수 있습니다. gcc는 특정 함수를 인라인 함수로 자동으로 최적화할 수 있기 때문에 원하는 프로브 효과가 달성되지 않을 수 있습니다.

4. The callback function of a probe point may modify the runtime context of the probed function, such as by modifying the kernel's data structure or saving register information before triggering the prober in the struct pt_regs structure. Therefore, kprobes can be used to install bug fixes or inject fault testing code.

5. kprobe는 프로브 포인트 함수를 처리할 때 다른 프로브 포인트의 콜백 함수를 다시 호출하는 것을 피합니다. **예를 들어, 프로브 포인트가 printk() 함수에 등록되어 있고 콜백 함수가 printk()를 다시 호출할 수 있는 경우 printk 프로브 포인트에 대한 콜백은 다시 트리거되지 않습니다.** Only the nmissed field in the kprobe structure will be incremented.

6. 뮤텍스 잠금 및 동적 메모리 할당은 k프로브의 등록 및 제거 과정에서 사용되지 않습니다.

7. kprobe 콜백 함수 실행 중에는 커널 선점이 비활성화되며, 인터럽트가 비활성화된 상태에서 실행될 수도 있는데, 이는 CPU 아키텍처에 따라 달라집니다. 따라서 상황에 상관없이 콜백 함수에서 CPU를 포기할 함수(세마포어, 뮤텍스 잠금 등)를 호출하지 마십시오;

8. kretprobe는 반환 주소를 미리 정의된 트램펄린 주소로 대체하여 구현되므로 스택 백트레이스와 gcc 인라인 함수 `__builtin_return_address()`는 probed 함수의 실제 반환 주소 대신 트램펄린의 주소를 반환합니다;

9. 함수의 호출 수와 반환 호출 수가 동일하지 않은 경우, 이러한 함수에 kretprobe를 등록하면 기대한 효과를 얻지 못할 수 있습니다. 예를 들어, `do_exit()` 함수는 문제가 발생하는 반면, `do_execve()` 함수와 `do_fork()` 함수는 문제가 발생하지 않습니다;

10. 함수에 들어가고 나올 때, CPU가 현재 작업에 속하지 않는 스택에서 실행 중인 경우 해당 함수에 kretprobe를 등록하면 예측할 수 없는 결과가 발생할 수 있습니다. 따라서 kprobe는 X86_64 아키텍처에서 `__switch_to()` 함수에 대한 kretprobe 등록을 지원하지 않으며 `-EINVAL`을 직접 반환합니다.

## kprobe Example
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

> `vmlinux.h` 헤더 파일의 위치는 어떻게 찾지??

이 코드는 리눅스 커널에서 실행되는 unlink 시스템 호출을 모니터링하고 캡처하는 데 사용되는 간단한 eBPF 프로그램입니다. unlink 시스템 호출은 파일을 삭제하는 데 사용됩니다. 이 eBPF 프로그램은 kprobe(커널 프로브)를 사용하여 do_unlinkat 함수의 진입점과 종료점에 후크를 배치하여 이 시스템 호출을 추적합니다.

먼저 vmlinux.h, bpf_helpers.h, bpf_tracing.h, bpf_core_read.h와 같은 필요한 헤더 파일을 가져옵니다. 그런 다음 커널에서 프로그램을 실행할 수 있도록 라이센스를 정의합니다.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

다음으로 do_unlinkat 함수에 진입할 때 트리거되는 `BPF_KPROBE(do_unlinkat)`라는 이름의 kprobe를 정의합니다. dfd(파일 기술자)와 name(파일명 구조 포인터) 두 개의 매개 변수가 필요합니다. 이 kprobe에서는 현재 프로세스의 PID(프로세스 식별자)를 검색한 다음, 파일 이름을 읽습니다. 마지막으로 `bpf_printk` 함수를 사용하여 커널 로그에 PID와 파일 이름을 인쇄합니다.

```c
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}
```

다음으로 do_unlinkat 함수에서 나갈 때 트리거되는 `BPF_KRETPROBE(do_unlinkat_exit)`라는 이름의 kretprobe를 정의합니다. 이 kretprobe의 목적은 함수의 반환 값(ret)을 캡처하는 것입니다. 우리는 다시 현재 프로세스의 PID를 구하고 `bpf_printk` 함수를 사용하여 커널 로그에 PID와 반환 값을 인쇄합니다.

```c
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

이 프로그램을 컴파일하려면 ecc 도구를 사용합니다:
```sh
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ ./ecc kprobe/kprobe-link.bpf.c 
INFO [ecc_rs::bpf_compiler] Compiling bpf object...
INFO [ecc_rs::bpf_compiler] Generating package json..
INFO [ecc_rs::bpf_compiler] Packing ebpf object and config into kprobe/package.json...
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ sudo ./ecli run kprobe/package.json 
[sudo] password for ebpf: 
INFO [faerie::elf] strtab: 0x61d symtab 0x658 relocs 0x6a0 sh_offset 0x6a0
INFO [bpf_loader_lib::skeleton::poller] Running ebpf program...
```

아래의 커맨드를 입력한 후, /sys/kernel/debug/trace/trace_pipe 파일에서 다음과 유사한 kprobe 데모 출력을 확인해야 합니다:

```sh
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ touch test1
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ rm test1
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ touch test2
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ rm test2
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ sudo cat /sys/kernel/debug/tracing/trace_pipe
[sudo] password for ebpf: 
rm-13992   [000] d...1  7379.126314: bpf_trace_printk: KPROBE ENTRY pid = 13992, filename = te
rm-13992   [000] d...1  7379.126373: bpf_trace_printk: KPROBE EXIT: pid = 13992, ret 
rm-14399   [001] d...1  7382.766562: bpf_trace_printk: KPROBE ENTRY pid = 14399, filename = te
rm-14399   [001] d...1  7382.766779: bpf_trace_printk: KPROBE EXIT: pid = 14399, ret = 0
```

## Summary

이 글의 예에서는 eBPF의 kprobe와 kretprobe를 이용하여 언링크 시스템 호출을 포착하는 방법에 대해 배웠습니다. 더 많은 예와 자세한 개발 가이드는 eunomia-bpf의 공식 문서(https://github.com/eunomia-bpf/eunomia-bpf 를 참조하십시오

이 기사는 eBPF 개발 입문 튜토리얼의 두 번째 부분입니다. 다음 기사에서는 fentry를 사용하여 eBPF에서 연결 해제 시스템 호출을 모니터링하고 캡처하는 방법에 대해 설명합니다.

eBPF 지식과 실무에 대해 더 알고 싶다면 https://github.com/eunomia-bpf/bpf-developer-tutorial 또는 웹사이트 https://eunomia.dev/tutorials/의 튜토리얼 코드 저장소를 방문하여 자세한 예제와 튜토리얼을 완료할 수 있습니다.