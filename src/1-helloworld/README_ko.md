# eBPF Tutorial by Example 1: Hello World, Framework and Development

이 블로그 게시물에서는 eBPF(Extended Berkeley Packet Filter)의 기본 프레임워크와 개발 프로세스에 대해 알아보겠습니다. eBPF는 리눅스 커널에서 실행되는 강력한 네트워크 및 성능 분석 도구로 개발자들은 커널 런타임에 사용자 정의 코드를 동적으로 로드하고 업데이트하고 실행할 수 있는 기능을 제공합니다. 이를 통해 개발자들은 효율적이고 안전한 커널 수준의 네트워크 모니터링, 성능 분석 및 문제 해결 기능을 구현할 수 있습니다.

이 글은 eBPF 튜토리얼의 두 번째 부분으로, 간단한 eBPF 프로그램을 작성하는 방법에 초점을 맞추고 전체 개발 과정을 실제 사례를 통해 시연할 것입니다. 이 튜토리얼을 읽기 전에 먼저 첫 번째 튜토리얼을 공부하여 eBPF의 개념을 배우는 것이 좋습니다.

eBPF 프로그램을 개발할 때 선택할 수 있는 개발 프레임워크는 BCC(BPF 컴파일러 모음) libpf, cilium/ebpf, eunomia-bpf 등 여러 가지가 있습니다. 이 도구들은 특성은 다르지만 기본적인 개발 과정은 비슷합니다. 다음 내용에서는 이러한 과정을 살펴보고 독자들이 eBPF 개발의 기본 기술을 습득하는 데 도움이 되는 Hello World 프로그램을 예로 들어보겠습니다.

이 자습서는 eBPF 프로그램의 기본 구조, 컴파일 및 로딩 과정, 사용자 공간과 커널 공간 간의 상호 작용, 디버깅 및 최적화 기법 등을 이해하는 데 도움이 될 것입니다. 이 자습서를 공부함으로써 eBPF 개발의 기본 지식을 숙달하고 추가 학습과 실습을 위한 탄탄한 기반을 마련할 수 있습니다.

## Preparation of eBPF Development Environment and Basic Development Process

eBPF 프로그램을 쓰기 시작하기 전에 적합한 개발 환경을 마련하고 eBPF 프로그램의 기본 개발 과정을 이해해야 합니다. 이 절에서는 이 과목들에 대해 자세히 소개하겠습니다.

### Installing the necessary software and tools

eBPF 프로그램을 개발하려면 다음 소프트웨어 및 도구를 설치해야 합니다:

- 리눅스 커널: eBPF는 커널 기술이므로 eBPF 기능을 지원하려면 비교적 새로운 버전의 리눅스 커널(미니엄 버전 4.8 이상, 제안 버전은 5.15+ 또는 6.2+)이 필요합니다.
가능하다면 새로운 버전의 Ubuntu(예: 23.10)를 설치하는 것이 좋습니다.
- LLVM 및 Clang: 이 도구들은 eBPF 프로그램을 컴파일하는 데 사용됩니다. 최신 버전의 LLVM 및 Clang을 설치하면 최상의 eBPF 지원을 받을 수 있습니다.

eBPF 프로그램은 크게 커널 공간 부분과 사용자 공간 부분으로 구성됩니다. 커널 공간 부분은 eBPF 프로그램의 실제 로직을 포함하고 사용자 공간 부분은 커널 공간 프로그램의 로딩, 실행 및 모니터링을 담당합니다.

BPF 컴파일러 모음, libpf, cilium/ebpf, eunomia-bpf와 같은 적절한 개발 프레임워크를 선택한 후 사용자 공간 및 커널 공간 프로그램을 개발할 수 있습니다. BCC 툴을 예로 들어 eBPF 프로그램의 기본 개발 프로세스를 소개하겠습니다:

1. **BCC 도구 설치**: Linux 배포판에 따라 BCC 설명서의 지침을 따라 BCC 도구와 그 종속성을 설치합니다.
2. **eBPF 프로그램 작성(C언어)**: Hello World 프로그램과 같은 간단한 eBPF 프로그램을 작성하려면 C언어를 사용합니다. 이 프로그램은 커널 공간에서 실행될 수 있으며 네트워크 패킷 계산과 같은 특정 작업을 수행할 수 있습니다.
3. **사용자 공간 프로그램 작성하기(파이썬이나 C 등)**: 파이썬이나 C 등의 언어를 사용하여 eBPF 프로그램의 로딩, 실행, 상호 작용을 담당하는 사용자 공간 프로그램을 작성합니다. 이 프로그램에서는 BCC에서 제공하는 API를 이용하여 커널 공간 eBPF 프로그램을 로딩하고 조작해야 합니다.
4. **eBPF 프로그램 컴파일**: BCC 툴을 사용하여 C언어로 작성된 eBPF 프로그램을 커널이 실행할 수 있는 바이트코드로 컴파일합니다. BCC는 실행 시에 소스코드에서 eBPF 프로그램을 동적으로 컴파일합니다.
5. **eBPF 프로그램 로드 및 실행**: 사용자 공간 프로그램에서 BCC에서 제공하는 API를 사용하여 컴파일된 eBPF 프로그램을 커널 공간에 로드한 후 실행합니다.
6. **eBPF 프로그램과의 상호 작용**: 사용자 공간 프로그램은 BCC에서 제공하는 API를 통해 eBPF 프로그램과 상호 작용하여 데이터 수집, 분석 및 표시 기능을 구현합니다. 예를 들어, BCC API를 사용하여 eBPF 프로그램의 Map 데이터를 읽어 네트워크 패킷 통계를 얻을 수 있습니다.
7. **eBPF 프로그램 언로딩**: eBPF 프로그램이 더 이상 필요하지 않을 때 사용자 공간 프로그램은 BCC API를 사용하여 커널 공간에서 언로딩해야 합니다.
8. **디버깅 및 최적화**: bpftool과 같은 도구를 사용하여 eBPF 프로그램을 디버깅하고 최적화하여 프로그램 성능과 안정성을 향상시킵니다.

위의 과정을 통해 BCC 툴을 이용하여 eBPF 프로그램을 개발, 컴파일, 실행 및 디버그할 수 있습니다. libpf, cilium/ebpf, eunomia-bpf 등 다른 프레임워크의 개발 과정은 유사하지만 약간 다르다는 점에 유의하시기 바랍니다. 따라서 프레임워크를 선택할 때는 각각의 공식 문서와 예시를 참조하시기 바랍니다.

이 과정을 수행하면 커널에서 실행되는 eBPF 프로그램을 개발할 수 있습니다. eunomia-bpf는 오픈 소스 eBPF 동적 로딩 런타임 및 개발 툴체인입니다. eBPF 프로그램의 개발, 구축, 배포 및 실행을 단순화하는 것을 목표로 합니다. libbpf CO-RE 경량 개발 프레임워크를 기반으로 하며 WASM(User Space Web Assembly) 가상 머신을 통해 eBPF 프로그램의 로딩 및 실행을 지원하고 배포를 위해 사전 컴파일된 eBPF 프로그램을 범용 JSON 또는 WASM 모듈에 패키징합니다. 시연 목적으로 eunomia-bpf를 사용할 것입니다.

## Download and Install eunomia-bpf Development Tools

다음 단계를 사용하여 eunomia-bpf를 다운로드하고 설치할 수 있습니다:

eBPF 프로그램을 실행하기 위한 ecli 도구를 다운로드합니다:

```sh
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
```
```sh
ebpf@ebpf:~$ ls
ecli  repo  workspace
ebpf@ebpf:~$ ./ecli -h
ecli subcommands, including run, push, pull

Usage: ecli [COMMAND_LINE]... [COMMAND]

Commands:
  run     run ebpf program
  client  Client operations
  push    Operations about pushing image to registry
  pull    Operations about pulling image from registry
  help    Print this message or the help of the given subcommand(s)

Arguments:
  [COMMAND_LINE]...  Not preferred. Only for compatibility to older versions. Command line to run. The executable could either be a local path or URL or `-` (read from stdin). The following arguments will be passed to the program

Options:
  -h, --help  Print help
```

eBPF 커널 코드를 구성 파일 또는 WASM 모듈로 컴파일하기 위한 컴파일러 툴체인을 다운로드합니다:

```sh
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
```
```sh
ebpf@ebpf:~$ ls
ecc  ecli  repo  workspace
ebpf@ebpf:~$ ./ecc -h
eunomia-bpf compiler

Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]

Arguments:
  <SOURCE_PATH>          path of the bpf.c file to compile
  [EXPORT_EVENT_HEADER]  path of the bpf.h header for defining event struct [default: ]

Options:
  -o, --output-path <OUTPUT_PATH>
          A directory to put the generated files; If not provided, will use the source location
  -v, --verbose
          Show more logs
  -y, --yaml
          output config skel file in yaml instead of JSON
      --header-only
          generate a bpf object for struct definition with header file only
      --wasm-header
          generate wasm include header
  -b, --btfgen
          fetch custom btfhub archive file
      --btfhub-archive <BTFHUB_ARCHIVE>
          directory to save btfhub archive file [default: /home/ebpf/.local/share/eunomia/btfhub-archive]
  -w, --workspace-path <WORKSPACE_PATH>
          custom workspace path
  -a, --additional-cflags <ADDITIONAL_CFLAGS>
          additional c flags for clang
  -c, --clang-bin <CLANG_BIN>
          path of clang binary [default: clang]
  -l, --llvm-strip-bin <LLVM_STRIP_BIN>
          path of the llvm-strip binary [default: llvm-strip]
  -n, --no-generate-package-json
          Don't generate a `package.json` containing the binary of the ELF file of the ebpf program
  -s, --standalone
          Produce standalone executable; Can only be used when `no_generate_package_json` is disabled
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version
```

참고: aarch64 플랫폼에 있는 경우 [ecc-arch64](https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc-aarch64) 및 [ecli-arch64](https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli-aarch64)를 사용하십시오.

도커 이미지를 사용하여 컴파일할 수도 있습니다:

```sh
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest # Compile using docker. `pwd` should contain *.bpf.c files and *.h files.
```

## Hello World - minimal eBPF program

커널에 메시지를 출력하는 간단한 eBPF 프로그램부터 시작하겠습니다. eunomia-bpf 컴파일러 툴체인을 사용하여 BPF 바이트코드 파일로 컴파일한 다음 ecli 툴을 사용하여 프로그램을 로드하고 실행합니다. 예를 들어 사용자 공간 프로그램을 일시적으로 무시할 수 있습니다.

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (pid_filter && pid != pid_filter)
        return 0;
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
    return 0;
}
```

이 프로그램은 handle_tp 함수를 정의하고 **SEC 매크로를 사용하여 sys_enter_write 트레이스 포인트에 붙입니다(즉, 쓰기 시스템 호출이 입력되면 실행됩니다).** 이 함수는 bpf_get_current_pid_tgid 및 bpf_printk 함수를 사용하여 쓰기 시스템 호출 호출의 프로세스 ID를 검색하고 커널 로그에 인쇄합니다.

- `bpf_trace_printk()`: trace_pipe(/sys/kernel/debug/trace/trace_pipe)에 정보를 출력하는 간단한 메커니즘입니다. 이것은 단순한 사용 사례에 적합하지만, 제한이 있습니다: 최대 3개의 매개 변수; 첫 번째 매개 변수는 %s(즉, 문자열)이어야 하며, trace_pipe는 커널에서 전역적으로 공유되므로 trace_pipe를 사용하는 다른 프로그램이 동시에 출력을 방해할 수 있습니다. 더 나은 접근 방식은 BPF_PERF_OUT()을 사용하는 것입니다.
- `void *ctx`: ctx는 원래 특정 유형의 매개 변수이지만 여기에는 사용되지 않기 때문에 void*라고 적습니다.
- `return 0;`: 0을 반환해야 합니다(이유를 알려면 #139 <https://github.com/iovisor/bcc/issues/139> 참조).

이 프로그램을 컴파일하고 실행하려면 ecc tool과 ecli 명령을 사용하면 됩니다. 먼저 Ubuntu/Debian에서 다음 명령을 실행합니다:

```sh
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ ./ecc minimal.bpf.c 
INFO [ecc_rs::bpf_compiler] Compiling bpf object...
INFO [ecc_rs::bpf_compiler] Generating package json..
INFO [ecc_rs::bpf_compiler] Packing ebpf object and config into package.json...
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ sudo ./ecli run package.json
INFO [faerie::elf] strtab: 0x26b symtab 0x2a8 relocs 0x2f0 sh_offset 0x2f0
INFO [bpf_loader_lib::skeleton::preload::section_loader] User didn't specify custom value for variable pid_filter, use the default one in ELF
INFO [bpf_loader_lib::skeleton::poller] Running ebpf program...
```

이 프로그램을 실행한 후 /sys/kernel/debug/trace/trace_pipe 파일을 확인하여 eBPF 프로그램의 출력을 볼 수 있습니다:

```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "BPF triggered sys_enter_write"
```
```sh
grep-7979    [001] d...1  4756.328011: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328017: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328023: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328029: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
 cat-7992    [000] d...1  4756.328033: bpf_trace_printk: BPF triggered sys_enter_write from PID 7992.
grep-7979    [001] d...1  4756.328035: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328041: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328047: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328053: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328059: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
grep-7979    [001] d...1  4756.328065: bpf_trace_printk: BPF triggered sys_enter_write from PID 7979.
```

참고: Linux 배포판(예: Ubuntu)에 추적 하위 시스템이 기본적으로 활성화되어 있지 않으면 출력이 표시되지 않을 수 있습니다. 이 기능을 활성화하려면 다음 명령을 사용하십시오:

```sh
sudo su
echo 1 > /sys/kernel/debug/tracing/tracing_on
```

```sh
ebpf@ebpf:~/workspace/bpf-developer-tutorial-source$ sudo cat  /sys/kernel/debug/tracing/tracing_on
1
```

## Basic Framework of eBPF Program

위에서 언급한 바와 같이 eBPF 프로그램의 기본 프레임워크는 다음을 포함합니다:

- 헤더 파일 포함: <linux/bpf.h> 및 <bpf/bpf_helpers.h> 헤더 파일 등을 포함해야 합니다.
- 라이센스 정의: 일반적으로 `Dual BSD/GPL`을 사용하여 라이센스를 정의해야 합니다.
- BPF 함수 정의: 예를 들어 `handle_tp`라는 이름의 BPF 함수를 정의해야 하며, 이 함수는 `void *ctx`를 매개 변수로 사용하고 int로 반환합니다. 이것은 일반적으로 C언어로 작성됩니다.
- BPF Helper Function 사용: BPF 기능에서 `bpf_get_current_pid_tgid()` 및 `bpf_printk()`와 같은 BPF Helper Function을 사용할 수 있습니다.
- 반환값

## Tracepoints

트레이스포인트는 커널 정적 계측 기법으로 커널 소스 코드에 존재하는 트레이스 함수에 불과하며, 본질적으로 소스 코드에 제어 조건이 삽입된 프로브 포인트이므로 추가적인 처리 기능으로 후처리가 가능합니다. 예를 들어 커널에서 가장 일반적인 정적 추적 방법은 로그 메시지를 출력하는 printk입니다. 예를 들어 시스템 호출, 스케줄러 이벤트, 파일 시스템 작업, 디스크 I/O의 시작과 끝에 트레이스포인트가 있습니다. 트레이스포인트는 2009년 리눅스 버전 2.6.32에서 처음 도입되었습니다. 트레이스포인트는 안정적인 API로 그 수가 제한되어 있습니다.

## GitHub Templates: Build eBPF Projects and Development Environments Easily

eBPF 프로젝트를 만들 때 환경을 설정하고 프로그래밍 언어를 선택하는 방법이 헷갈리시나요? 걱정하지 마세요, 새로운 eBPF 프로젝트를 빠르게 시작할 수 있도록 일련의 GitHub 템플릿을 준비했습니다. 시작하려면 GitHub에서 Use this template 버튼을 클릭하십시오.

- <https://github.com/eunomia-bpf/libbpf-starter-template>: eBPF project template based on the C language and libbpf framework.
- <https://github.com/eunomia-bpf/cilium-ebpf-starter-template>: eBPF project template based on the C language and cilium/ebpf framework.
- <https://github.com/eunomia-bpf/libbpf-rs-starter-template>: eBPF project template based on the Rust language and libbpf-rs framework.
- <https://github.com/eunomia-bpf/eunomia-template>: eBPF project template based on the C language and eunomia-bpf framework.

이러한 스타터 템플릿에는 다음과 같은 기능이 포함됩니다:

- 하나의 명령으로 프로젝트를 구축하기 위한 Makefile.
- eBPF 프로젝트를 위한 컨테이너화된 환경을 자동으로 만들고 이를 Github Packages에 게시하기 위한 Docker 파일 - 빌드, 테스트 및 릴리스 프로세스를 자동화하는 데 사용되는 GitHub Actions
- eBPF 개발에 필요한 모든 종속성

> 기존 저장소를 템플릿으로 설정함으로써 사용자와 다른 사람들은 동일한 기본 구조를 가진 새로운 저장소를 빠르게 생성하여 수동 생성 및 구성의 지루한 과정을 없앨 수 있습니다. GitHub 템플릿 저장소를 사용하면 개발자들은 설정 및 구조에 시간을 낭비하지 않고 프로젝트의 핵심 기능과 논리에 집중할 수 있습니다. 템플릿 저장소에 대한 자세한 내용은 공식 문서(https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-template-repository 를 참조하십시오.

## Summary

eBPF 프로그램의 개발 및 사용 과정은 다음 단계로 요약할 수 있습니다:

- eBPF 프로그램의 인터페이스 및 유형 정의: 여기에는 eBPF 프로그램의 인터페이스 기능 정의, eBPF 커널 맵 및 공유 메모리(perf 이벤트) 정의 및 구현, eBPF 커널 도우미 기능 정의 및 사용이 포함됩니다.
- eBPF 프로그램의 코드 작성: eBPF 프로그램의 주요 로직 작성, eBPF 커널 맵에 대한 읽기 및 쓰기 작업 구현, eBPF 커널 도우미 함수 사용 등이 이에 해당합니다.
- eBPF 프로그램 컴파일: 여기에는 eBPF 컴파일러(예: clang)를 사용하여 eBPF 프로그램 코드를 eBPF 바이트 코드로 컴파일하고 실행 가능한 eBPF 커널 모듈을 생성하는 것이 포함됩니다. eBPF 프로그램을 컴파일하기 위해 clang 컴파일러를 호출합니다.
- eBPF 프로그램을 커널에 로드합니다. 여기에는 컴파일된 eBPF 커널 모듈을 리눅스 커널에 로드하고 지정된 커널 이벤트에 eBPF 프로그램을 첨부하는 것이 포함됩니다.
- eBPF 프로그램 사용: eBPF 프로그램의 실행을 모니터링하고 eBPF 커널 맵과 공유 메모리를 사용하여 데이터를 교환하고 공유합니다.
- 실제 개발에서는 컴파일 및 로딩 파라미터 구성, eBPF 커널 모듈 및 커널 맵 관리, 기타 고급 기능 사용 등의 추가 단계가 있을 수 있습니다.

BPF 프로그램의 실행은 커널 공간에서 발생하므로 BPF 프로그램을 작성하고 컴파일하고 디버그하기 위해서는 특별한 도구와 기술이 필요합니다. eunomia-bpf는 개발자가 BPF 프로그램을 빠르고 쉽게 작성하고 실행할 수 있도록 도와줄 수 있는 오픈 소스 BPF 컴파일러이자 툴킷입니다.

또한 튜토리얼 코드 저장소 https://github.com/eunomia-bpf/bpf-developer-tutorial 또는 웹사이트 https://eunomia.dev/tutorials/ 또는 웹사이트 https://eunomia.dev/tutorials/를 방문하여 자세한 예제와 전체 튜토리얼을 확인할 수 있으며, 이 모든 것은 오픈 소스입니다. eBPF 기술을 더 잘 이해하고 숙달할 수 있도록 eBPF 개발 관행에 대해 계속해서 더 많은 정보를 공유하겠습니다.