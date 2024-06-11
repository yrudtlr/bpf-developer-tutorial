# eBPF Tutorial by Example 5: Capturing readline Function Calls with Uprobe

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구로, 개발자가 사용자 정의 코드를 런타임에 동적으로 로드, 업데이트 및 실행할 수 있습니다.

이 기사는 eBPF Tutorial by Example의 다섯 번째 부분으로, 주로 uprobe를 사용하여 bash에서 readline 함수 호출을 캡처하는 방법을 소개합니다.

## What is uprobe

uprobe는 사용자 공간 프로그램에서 동적 instrumentation을 허용하는 사용자 공간 프로브입니다. 프로브 위치에는 함수 진입, 특정 오프셋 및 함수 반환이 포함됩니다. uprobe를 정의하면 커널은 첨부된 명령어에 빠른 중단점 명령어(x86 머신의 int3 명령어)를 생성합니다. **프로그램이 이 명령어를 실행하면 커널은 이벤트를 트리거하여 프로그램이 커널 모드로 진입하고 콜백 함수를 통해 프로브 함수를 호출합니다. 프로브 함수를 실행한 후 프로그램은 사용자 모드로 돌아가 후속 명령어를 계속 실행합니다.**

uprobe is file-based. When a function in a binary file is traced, all processes that use the file are instrumented, including those that have not yet been started, allowing system calls to be tracked system-wide.

uprobe는 HTTP/2 트래픽(헤더가 인코딩되어 커널에서 디코딩할 수 없음) 및 HTTPS 트래픽(암호화되어 커널에서 디코딩할 수 없음)과 같이 커널 모드 프로브로 해결할 수 없는 일부 트래픽을 사용자 모드에서 구문 분석하는 데 적합합니다. 자세한 내용은 eBPF 튜토리얼의 예제: [eBPF Tutorial by Example: Capturing SSL/TLS Plaintext Data from Multiple Libraries with Uprobe.](../30-sslsniff/README.md) 예제를 참조하십시오.

커널 모드 eBPF 런타임에서 uprobe는 상대적으로 큰 성능 오버헤드를 유발할 수도 있습니다. 이 경우 bpftime과 같이 사용자 모드 eBPF 런타임을 사용하는 것도 고려할 수 있습니다. bpftime은 LLVM JIT/AOT 기반의 사용자 모드 eBPF 런타임입니다. 사용자 모드에서 eBPF 프로그램을 실행할 수 있고 커널 모드 eBPF와 호환되어 커널 모드와 사용자 모드 간의 컨텍스트 전환을 피할 수 있어 eBPF 프로그램의 실행 효율이 10배 향상됩니다.

## Capturing readline Function Calls in bash using uprobe

routbe는 사용자 공간 기능 호출을 캡처하는 데 사용되는 eBPF 프로브로 사용자 공간 프로그램에서 호출하는 시스템 기능을 캡처할 수 있습니다.

예를 들어, uprobe를 사용하여 bash에서 읽기 라인 함수 호출을 캡처하고 사용자로부터 명령줄 입력을 받을 수 있습니다. 예제 코드는 다음과 같습니다:

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    u32 pid;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(str, sizeof(str), ret); 

    bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

    return 0;
};

char LICENSE[] SEC("license") = "GPL";
```

이 코드의 목적은 bash의 읽기 라인 함수가 반환될 때 지정된 BPF_PROBE 함수(printret 함수)를 실행하는 것입니다.

printret 함수에서는 먼저 readline 함수를 호출하는 프로세스의 프로세스 이름과 프로세스 ID를 얻습니다. 그런 다음 bpf_probe_read_user_str 함수를 사용하여 사용자 입력 명령줄 문자열을 읽습니다. 마지막으로 bpf_printk 함수를 사용하여 프로세스 ID, 프로세스 이름 및 입력 명령줄 문자열을 인쇄합니다.

**또한 우리는 SEC 매크로를 사용하여 uprobe 프로브를 정의하고 BPF_KRETPROBE 매크로를 사용하여 프로브 함수를 정의해야 합니다.** 위 코드의 SEC 매크로에서 uprobe의 종류, 캡처할 이진 파일의 경로, 캡처할 함수의 이름을 지정해야 합니다. 예를 들어 위 코드의 SEC 매크로의 정의는 다음과 같습니다:

```c
SEC("uprobe//bin/bash:readline")
```

이는 읽기 라인 함수를 /bin/bash 이진 파일에 캡처하려는 것을 나타냅니다.

다음으로 BPF_KRETPROBE 매크로를 사용하여 프로브 함수를 정의해야 합니다. 예를 들어 다음과 같습니다:

```c
BPF_KRETPROBE(printret, const void *ret)
```

여기서 `printret`은 프로브 함수의 이름이고 `const void *ret`은 캡처된 함수의 반환 값을 나타내는 프로브 함수의 파라미터입니다.

그런 다음 bpf_get_current_comm 함수를 사용하여 현재 작업의 이름을 가져와 comm 배열에 저장합니다.

```c
bpf_get_current_comm(&comm, sizeof(comm));
```

bpf_get_current_pid_tgid 함수를 사용하여 현재 프로세스의 PID를 가져와 Pid 변수에 저장합니다.

```c
pid = bpf_get_current_pid_tgid() >> 32;
```

bpf_probe_read_user_str 함수를 사용하여 사용자 공간에서 읽기 라인 함수의 반환 값을 읽어 str 배열에 저장합니다.

```c
bpf_probe_read_user_str(str, sizeof(str), ret);
```

마지막으로 bpf_printk 함수를 사용하여 PID, 작업명 및 사용자 입력 문자열을 출력합니다.

```c
bpf_printk("PID %d (%s) read: %s ", pid, comm, str);
```

```sh
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ hello
Command 'hello' not found, but can be installed with:
sudo snap install hello              # version 2.10, or
sudo apt  install hello              # version 2.10-2ubuntu4
sudo apt  install hello-traditional  # version 2.10-5
See 'snap info hello' for additional versions.
webpf@ebpf:~/workspace/bpf-developer-tutorial-source$ world
Command 'world' not found, but can be installed with:
sudo snap install world
```
```sh
bash-26651   [001] d...1 16251.029581: bpf_trace_printk: PID 26651 (bash) read: hello 
bash-26651   [001] d...1 16251.627685: bpf_trace_printk: PID 26651 (bash) read: world
```

## Summary

위 코드에서 우리는 SEC 매크로를 사용하여 uprobe 프로브를 정의하였는데, 이는 캡처할 사용자 공간 프로그램(bin/bash)과 캡처할 함수(readline)를 지정합니다. 또한 BPF_KRETPROBE 매크로를 사용하여 readline 함수의 리턴 값을 처리하기 위한 콜백 함수(printret)를 정의하였습니다. 이 함수는 readline 함수의 리턴 값을 검색하여 커널 로그에 인쇄할 수 있습니다. 이러한 방식으로 eBPF를 사용하여 bash의 리드라인 함수 호출을 캡처하고 bash에서 사용자가 입력한 명령줄을 얻을 수 있습니다.
