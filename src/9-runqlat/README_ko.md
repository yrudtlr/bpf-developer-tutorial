# eBPF Tutorial by Example 9: Capturing Scheduling Latency and Recording as Histogram

eBPF(Extended Berkeley Packet Filter)는 리눅스 커널의 강력한 네트워크 및 성능 분석 도구입니다. 이를 통해 개발자가 런타임에 사용자 정의 코드를 동적으로 로드하고 업데이트하고 실행할 수 있습니다.

runqlat은 리눅스 시스템의 스케줄링 성능을 분석하는 데 사용되는 eBPF 도구입니다. 특히 runqlat은 CPU에 스케줄링되기 전에 작업이 실행 대기열에서 대기하는 시간을 측정하는 데 사용됩니다. 이 정보는 성능 병목 현상을 식별하고 리눅스 커널 스케줄링 알고리즘의 전반적인 효율성을 향상시키는 데 매우 유용합니다.

