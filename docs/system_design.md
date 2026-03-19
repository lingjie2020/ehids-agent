# eHIDS Agent 系统设计文档

> 版本：v1.0  
> 语言：Go + eBPF C  
> 适用内核：Linux ≥ 4.15（部分功能需 5.2+）

---

## 目录

1. [项目概述](#1-项目概述)
2. [整体架构](#2-整体架构)
3. [目录结构](#3-目录结构)
4. [核心接口设计](#4-核心接口设计)
   - 4.1 [IModule 接口](#41-imodule-接口)
   - 4.2 [IEventStruct 接口](#42-ieventstruct-接口)
   - 4.3 [IClose 接口](#43-iclose-接口)
5. [模块基类设计（Module）](#5-模块基类设计module)
   - 5.1 [字段说明](#51-字段说明)
   - 5.2 [生命周期管理](#52-生命周期管理)
   - 5.3 [事件读取机制](#53-事件读取机制)
   - 5.4 [事件输出（Write）](#54-事件输出write)
6. [模块注册机制](#6-模块注册机制)
7. [各探针模块设计](#7-各探针模块设计)
   - 7.1 [EBPFProbeKTCP — TCP 连接追踪](#71-ebpfprobektcp--tcp-连接追踪)
   - 7.2 [EBPFProbeKTCPSec — 安全层套接字监控](#72-ebpfprobektcpsec--安全层套接字监控)
   - 7.3 [EBPFProbeKUDP — UDP 数据包捕获](#73-ebpfprobekudp--udp-数据包捕获)
   - 7.4 [EBPFProbeUDNS — DNS 解析捕获（uprobe）](#74-ebpfprobeudns--dns-解析捕获uprobe)
   - 7.5 [EBPFProbeUJavaRASP — Java RASP 命令执行检测](#75-ebpfprobeujavarasp--java-rasp-命令执行检测)
   - 7.6 [EBPFProbeProc — 进程创建监控](#76-ebpfprobeproc--进程创建监控)
   - 7.7 [EBPFProbeBPFCall — BPF 系统调用监控](#77-ebpfprobebpfcall--bpf-系统调用监控)
8. [事件结构体设计](#8-事件结构体设计)
9. [内核态 eBPF 程序设计](#9-内核态-ebpf-程序设计)
10. [数据流程](#10-数据流程)
11. [新增探针开发指南](#11-新增探针开发指南)
12. [技术选型与依赖](#12-技术选型与依赖)
13. [编译与运行](#13-编译与运行)

---

## 1. 项目概述

**eHIDS Agent** 是一个基于 eBPF 内核技术实现的主机入侵检测系统（HIDS）演示项目，旨在展示如何利用 eBPF 的 kprobe、kretprobe、uprobe、uretprobe 以及 tracepoint 等挂载机制，对主机上的网络行为、进程行为、DNS 查询及 Java 命令执行等场景进行实时监控与事件上报。

**核心目标：**

- 以最少的内核侵入性捕获安全相关事件。
- 提供清晰的插件化框架，开发者只需实现三个文件即可接入新探针。
- 事件处理层与采集层解耦，支持自定义上报策略（日志、ES、Kafka 等）。

**当前支持的监控能力：**

| 能力 | 探针类型 | Hook 点 |
|------|----------|---------|
| TCP 连接追踪 | kprobe | `tcp_set_state` |
| 套接字连接安全审计 | kprobe | `security_socket_connect` |
| UDP/DNS 数据包捕获 | kprobe/kretprobe | `udp_recvmsg` |
| DNS 域名解析捕获 | uprobe/uretprobe | `getaddrinfo`（libc） |
| Java 命令执行检测 | uprobe | `JDK_execvpe`（libjava.so） |
| 进程创建监控 | kretprobe | `copy_process` |
| BPF 系统调用审计 | tracepoint | `sys_enter_bpf` |

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                          用户空间 (Go)                           │
│                                                                  │
│   main.go                                                        │
│     │                                                            │
│     ├── GetModules()  ──→  module 注册表 (map[string]IModule)    │
│     │                                                            │
│     └── 每个 IModule:                                            │
│           Init(ctx, logger)                                      │
│           └── go module.Run()                                    │
│                 ├── child.Start()  ── 加载 eBPF 字节码           │
│                 │                    挂载 hook 点                │
│                 ├── go run()       ── 监听 ctx.Done，关闭资源    │
│                 └── readEvents()   ── 从 BPF Map 读取事件        │
│                       ├── perfEventReader()  (PerfEventArray)    │
│                       └── ringbufEventReader() (RingBuf)         │
│                             │                                    │
│                             ├── child.Decode()                   │
│                             │     └── IEventStruct.Decode()      │
│                             └── Module.Write()  ── 日志输出      │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                    内核空间 (eBPF C)                              │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌─────────────┐   │
│   │ kprobe/  │  │ kprobe/  │  │  uprobe/  │  │ tracepoint  │   │
│   │ kretprobe│  │ security │  │  uretprobe│  │ sys_enter_  │   │
│   │ tcp/udp/ │  │ _socket_ │  │  libc/    │  │ bpf         │   │
│   │ process  │  │ connect  │  │  libjava  │  │             │   │
│   └────┬─────┘  └────┬─────┘  └─────┬─────┘  └──────┬──────┘   │
│        │             │              │               │           │
│        └─────────────┴──────────────┴───────────────┘           │
│                              │                                   │
│                    BPF Maps (PerfEventArray / RingBuf)           │
└─────────────────────────────────────────────────────────────────┘
```

**架构核心思想：**

1. **内核态**：使用 C 编写 eBPF 程序，通过 clang/LLVM 编译为 eBPF 字节码（`.o` 文件），使用 go-bindata 工具嵌入到 Go 二进制中。
2. **用户态**：使用 Go 编写，通过 `ebpfmanager` 库将字节码加载到内核、挂载到 hook 点，并通过 BPF Map 读取内核产生的事件。
3. **事件管道**：内核写 → BPF Map → Go 读 → 解码 → 上报。
4. **插件化**：每个探针通过 `init()` 函数在启动时自动注册到全局 module 注册表。

---

## 3. 目录结构

```
ehids-agent/
├── main.go                   # 程序入口：注册信号、遍历并启动所有模块
├── go.mod                    # Go 依赖声明
├── Makefile                  # 编译脚本（eBPF → 字节码 → Go 二进制）
├── assets/
│   └── ebpf_probe.go         # go-bindata 生成的资源文件（内嵌 .o 字节码）
├── kern/                     # 内核态 eBPF C 代码
│   ├── ehids_agent.h         # 统一头文件入口（包含所有内核头）
│   ├── common.h              # 公共宏定义与数据结构
│   ├── vmlinux.h             # 内核数据结构（BTF 生成）
│   ├── bpf/                  # BPF 辅助头文件（cilium/ebpf 提供）
│   ├── tcp_set_state_kern.c  # TCP 状态追踪
│   ├── sec_socket_connect_kern.c  # 套接字连接安全层监控
│   ├── udp_lookup_kern.c     # UDP 包捕获（DNS）
│   ├── dns_lookup_kern.c     # DNS 解析（uprobe on getaddrinfo）
│   ├── proc_kern.c           # 进程创建追踪
│   ├── java_exec_kern.c      # Java 命令执行追踪（uprobe on JDK_execvpe）
│   └── bpf_call_kern.c       # BPF 系统调用追踪
├── user/                     # 用户态 Go 代码
│   ├── imodule.go            # IModule 接口 + Module 基类
│   ├── ievent.go             # IEventStruct 接口
│   ├── iclose.go             # IClose 接口
│   ├── register.go           # 全局模块注册表
│   ├── common.go             # 公共常量（地址族、probe 类型等）
│   ├── bpf_cmd.go            # BPF 命令枚举
│   ├── probe_ktcp.go         # TCP 探针
│   ├── probe_ktcp_sec.go     # 安全套接字探针
│   ├── probe_kudp.go         # UDP 探针（当前未注册）
│   ├── probe_udns.go         # DNS 探针
│   ├── probe_ujava_rasp.go   # Java RASP 探针
│   ├── probe_proc.go         # 进程探针
│   ├── probe_bpf_call.go     # BPF 调用探针
│   ├── event_tcp.go          # TCP 事件结构体
│   ├── event_ktcp_sec.go     # 安全套接字事件结构体（IPV4/IPV6/Other）
│   ├── event_kudp.go         # UDP 事件结构体
│   ├── event_udns.go         # DNS 事件结构体
│   ├── event_java_rasp.go    # Java RASP 事件结构体
│   ├── event_proc.go         # 进程事件结构体
│   └── event_bpf_call.go     # BPF 调用事件结构体
├── user/bytecode/            # 编译好的 eBPF 字节码 .o 文件
├── examples/
│   └── Main.java             # Java RASP 测试用例
├── docs/
│   └── system_design.md      # 本系统设计文档
└── images/                   # README 配图
```

---

## 4. 核心接口设计

### 4.1 IModule 接口

定义于 `user/imodule.go`，是所有探针模块必须实现的顶层接口。

```go
type IModule interface {
    // Init 初始化模块，传入上下文和日志器
    Init(context.Context, *log.Logger) error

    // Name 返回模块名称，用于注册表键和日志标识
    Name() string

    // Run 启动完整的采集-读取-上报流程（阻塞在事件读取循环中）
    Run() error

    // Start 加载 eBPF 字节码并挂载到 hook 点（由子类实现）
    Start() error

    // Stop 停止模块（基类默认为空操作，预留扩展）
    Stop() error

    // Close 释放 eBPF 资源（停止 ebpfmanager、关闭 Map 读取器）
    Close() error

    // SetChild 设置子对象引用，用于基类调用子类方法（模板方法模式）
    SetChild(module IModule)

    // Decode 将 BPF Map 中的原始字节解码为可读字符串
    Decode(*ebpf.Map, []byte) (string, error)

    // Events 返回该模块监听的所有 BPF Map 列表
    Events() []*ebpf.Map

    // DecodeFun 根据 BPF Map 返回对应的事件解码器
    DecodeFun(p *ebpf.Map) (IEventStruct, bool)
}
```

**设计说明：**

- 采用**模板方法模式**：`Module` 基类实现通用逻辑（`Run`、`readEvents`、`Decode`、`Write`），子类只需重写 `Start`、`Events`、`DecodeFun`、`Close` 四个方法。
- `SetChild` + `child` 字段是基类调用子类多态方法的桥梁，避免在 Go 中直接使用接口组合时丢失子类实现。

### 4.2 IEventStruct 接口

定义于 `user/ievent.go`，所有事件结构体必须实现此接口。

```go
type IEventStruct interface {
    // Decode 将内核写入 BPF Map 的原始字节数组解析为 Go 结构体字段
    Decode(payload []byte) (err error)

    // String 将结构体格式化为人类可读字符串，用于日志输出
    String() string

    // Clone 创建一个新的空白实例，供并发读取时独立使用
    Clone() IEventStruct
}
```

**设计说明：**

- `Clone()` 机制确保每次事件处理都使用独立的结构体实例，避免并发写入同一对象导致数据竞争。
- `Decode()` 使用 `encoding/binary.Read` 按小端序逐字段解析，与内核 C 结构体的内存布局严格对齐。

### 4.3 IClose 接口

定义于 `user/iclose.go`，为统一资源关闭提供抽象。

```go
type IClose interface {
    Close() error
}
```

---

## 5. 模块基类设计（Module）

`Module` 结构体是所有探针的嵌入式基类，实现了 `IModule` 中除 `Start`、`Events`、`DecodeFun`、`Close` 之外的所有通用逻辑。

### 5.1 字段说明

```go
type Module struct {
    opts   *ebpf.CollectionOptions  // eBPF 集合加载选项（当前未使用，预留扩展）
    reader []IClose                  // 待关闭的资源列表（预留扩展）
    ctx    context.Context           // 全局上下文，用于感知关闭信号
    logger *log.Logger               // 日志器
    child  IModule                   // 子类引用（模板方法模式的核心）
    name   string                    // 探针名称，如 "EBPFProbeKTCP"
    mType  string                    // 探针类型，如 "kprobe"、"uprobe"、"tracepoint"
}
```

### 5.2 生命周期管理

```
                    ┌─ main.go ─────────────────────────────┐
                    │                                        │
                    │  module.Init(ctx, logger)              │
                    │       │                                │
                    │       └→ 保存 ctx 和 logger            │
                    │                                        │
                    │  go module.Run()                       │
                    │       │                                │
                    │       ├→ child.Start()                 │
                    │       │    └→ 加载 eBPF .o 字节码       │
                    │       │    └→ bpfManager.Start()       │
                    │       │    └→ 挂载到内核 hook 点        │
                    │       │    └→ initDecodeFun()          │
                    │       │                                │
                    │       ├→ go run()  ←── 监听 ctx.Done   │
                    │       │    └→ child.Close()            │
                    │       │         └→ bpfManager.Stop()  │
                    │       │                                │
                    │       └→ readEvents()  ←── 阻塞读取    │
                    │                                        │
                    │  <-stopper (SIGTERM/SIGINT)            │
                    │       └→ cancelFun()                   │
                    │             └→ ctx.Done() 触发         │
                    └────────────────────────────────────────┘
```

**关键设计决策：**

- `go run()` 必须在 `readEvents()` 之前启动，因为 `readEvents()` 会阻塞当前 goroutine。若顺序颠倒，上下文取消信号将无法被处理，导致关闭时资源无法释放。
- 关闭时调用 `child.Close()`（而非 `child.Stop()`），`Close()` 会执行 `bpfManager.Stop(manager.CleanAll)`，这会关闭所有 BPF Map 的文件描述符，从而使 `rd.Read()` 返回 `ErrClosed` 错误，事件读取循环自然退出。

### 5.3 事件读取机制

`readEvents()` 根据 BPF Map 的类型自动选择读取方式：

```
child.Events()
    │
    ├── Map.Type() == RingBuf      → go ringbufEventReader()
    │                                    └→ ringbuf.NewReader(em)
    │                                    └→ rd.Read() → Decode → Write
    │
    └── Map.Type() == PerfEventArray → go perfEventReader()
                                          └→ perf.NewReader(em, pagesize)
                                          └→ rd.Read() → 检查 LostSamples
                                                       → Decode → Write
```

| Map 类型 | 适用场景 | 特点 |
|----------|----------|------|
| `PerfEventArray` | 高频网络事件（TCP、DNS、安全套接字） | 每 CPU 一个 ring buffer，内核写入快；可感知丢包（`LostSamples`） |
| `RingBuf` | 进程创建事件 | 全局单 ring buffer，内核 5.8+ 支持；单次分配，效率更高 |

### 5.4 事件输出（Write）

```go
func (this *Module) Write(result string) {
    s := fmt.Sprintf("probeName:%s, probeTpye:%s, %s", this.name, this.mType, result)
    this.logger.Println(s)
}
```

**扩展点：** 通过覆盖 `Write` 方法或修改 `logger`，可将事件上报至 ES、Kafka、gRPC 等任意后端，实现与采集逻辑的完全解耦。

---

## 6. 模块注册机制

采用 **Go `init()` 函数自动注册** 模式，无需手动维护探针列表。

```go
// user/register.go
var modules = make(map[string]IModule)

func Register(p IModule) { ... }
func GetModules() map[string]IModule { return modules }
```

每个探针文件末尾均有：

```go
func init() {
    mod := &M<ProbeType>Probe{}
    mod.name = "EBPFProbe<Name>"
    mod.mType = PROBE_TYPE_KPROBE  // 或 UPROBE / TP
    Register(mod)
}
```

**注册流程：**

```
程序启动
  └→ Go 运行时执行所有 init() 函数
       └→ 每个探针的 init() 调用 Register()
            └→ 写入全局 modules map
                 └→ main.go 中 GetModules() 遍历并启动所有模块
```

**已注册的探针列表：**

| 模块名称 | 探针类型 | 状态 |
|----------|----------|------|
| `EBPFProbeKTCP` | kprobe | ✅ 已注册 |
| `EBPFProbeKTCPSec` | kprobe | ✅ 已注册 |
| `EBPFProbeKUDP` | kprobe | ⚠️ 代码存在，`init()` 中未调用 `Register` |
| `EBPFProbeUDNS` | uprobe | ✅ 已注册 |
| `EBPFProbeUJavaRASP` | uprobe | ✅ 已注册 |
| `EBPFProbeProc` | kprobe | ✅ 已注册 |
| `EBPFProbeBPFCall` | tracepoint | ✅ 已注册 |

---

## 7. 各探针模块设计

所有探针模块遵循统一的结构：

```go
type M<Name>Probe struct {
    Module                          // 嵌入基类
    bpfManager        *manager.Manager  // eBPF 程序管理器
    bpfManagerOptions manager.Options   // 管理器配置
    eventFuncMaps     map[*ebpf.Map]IEventStruct  // Map → 解码器映射
    eventMaps         []*ebpf.Map                 // 该探针监听的 Map 列表
}
```

### 7.1 EBPFProbeKTCP — TCP 连接追踪

- **文件**：`kern/tcp_set_state_kern.c` + `user/probe_ktcp.go` + `user/event_tcp.go`
- **Hook 类型**：kprobe
- **Hook 函数**：`tcp_set_state`
- **BPF Map**：
  - `events`（PerfEventArray）：输出 TCP 连接事件
  - `conns`（HashMap）：临时存储连接状态，用于关联入口/出口数据
- **捕获数据**：连接开始/结束时间、PID、本地/远端 IP 和端口、收发字节数、进程名、UID、地址族

### 7.2 EBPFProbeKTCPSec — 安全层套接字监控

- **文件**：`kern/sec_socket_connect_kern.c` + `user/probe_ktcp_sec.go` + `user/event_ktcp_sec.go`
- **Hook 类型**：kprobe
- **Hook 函数**：`security_socket_connect`（LSM/SELinux 钩子，在实际连接建立前触发）
- **BPF Map**：
  - `ipv4_events`（PerfEventArray）：IPv4 连接尝试
  - `ipv6_events`（PerfEventArray）：IPv6 连接尝试
  - `other_socket_events`（PerfEventArray）：其他协议族（AF_FILE 等）
- **捕获数据**：时间戳、PID、UID、地址族、本地/远端地址及端口、进程名

### 7.3 EBPFProbeKUDP — UDP 数据包捕获

- **文件**：`kern/udp_lookup_kern.c` + `user/probe_kudp.go` + `user/event_kudp.go`
- **Hook 类型**：kprobe + kretprobe
- **Hook 函数**：`udp_recvmsg`（入口 + 返回）
- **BPF Map**：`dns_events`（PerfEventArray）
- **捕获数据**：完整 UDP 包内容，在用户态用 `rawdns` 库解析为 DNS 结构
- **备注**：当前 `init()` 中未调用 `Register(mod)`，模块不会自动启动，可手动启用

### 7.4 EBPFProbeUDNS — DNS 解析捕获（uprobe）

- **文件**：`kern/dns_lookup_kern.c` + `user/probe_udns.go` + `user/event_udns.go`
- **Hook 类型**：uprobe + uretprobe
- **Hook 目标**：`/lib/x86_64-linux-gnu/libc.so.6` 中的 `getaddrinfo` 函数
- **BPF Map**：`events`（PerfEventArray）
- **捕获数据**：PID、UID、地址族、解析结果 IP（IPv4/IPv6）、请求的域名（HOST 字段，最长 80 字节）
- **优势**：在 DNS 响应被应用层处理后捕获，能同时获取域名和解析结果 IP

### 7.5 EBPFProbeUJavaRASP — Java RASP 命令执行检测

- **文件**：`kern/java_exec_kern.c` + `user/probe_ujava_rasp.go` + `user/event_java_rasp.go`
- **Hook 类型**：uprobe
- **Hook 目标**：`/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so`
  - 函数：`JDK_execvpe`，偏移量：`0x19C30`（适用于 OpenJDK 1.8.0_292）
- **BPF Map**：`jdk_execvpe_events`（PerfEventArray）
- **捕获数据**：PID、执行模式（`MODE_FORK` / `MODE_POSIX_SPAWN` / `MODE_VFORK` / `MODE_CLONE`）、被执行的文件路径
- **应用场景**：检测 Java 应用在运行时通过 Runtime.exec() 等方式执行系统命令（典型 RASP 检测场景）
- **注意**：偏移量与 libjava.so 版本强绑定，其他版本需重新定位偏移地址

### 7.6 EBPFProbeProc — 进程创建监控

- **文件**：`kern/proc_kern.c` + `user/probe_proc.go` + `user/event_proc.go`（`ForkProcEvent`）
- **Hook 类型**：kretprobe
- **Hook 函数**：`copy_process`（`fork()`/`clone()` 的内核实现）
- **BPF Map**：`ringbuf_proc`（**RingBuf**，而非 PerfEventArray）
- **捕获数据**：
  - 子进程：PID、TGID
  - 父进程：PID、TGID
  - 祖父进程：PID、TGID
  - UID、GID、UTS 命名空间编号、启动时间、进程名、命令行、可执行文件路径

### 7.7 EBPFProbeBPFCall — BPF 系统调用监控

- **文件**：`kern/bpf_call_kern.c` + `user/probe_bpf_call.go` + `user/event_bpf_call.go`
- **Hook 类型**：tracepoint
- **Hook 点**：`tracepoint/syscalls/sys_enter_bpf`
- **BPF Map**：`events`（PerfEventArray，最大 64 条）
- **捕获数据**：BPF 命令类型（`BPF_MAP_CREATE`、`BPF_PROG_LOAD` 等 34 种）、进程三级调用链（PID/TGID/PPID）、UID/GID、进程名、命令行、主机名
- **事件处理**：该模块直接在 `dataHandler` 回调中解码并上报，不经过通用的 `perfEventReader` 路径
- **应用场景**：检测系统中所有 eBPF 程序的加载行为，识别潜在的 eBPF rootkit 活动

---

## 8. 事件结构体设计

所有事件结构体实现 `IEventStruct` 接口，字段布局与内核 C 结构体严格对应（小端序）。

### 8.1 事件类型汇总

| 结构体名 | 对应探针 | 文件 | 关键字段 |
|----------|----------|------|----------|
| `TCPEvent` | EBPFProbeKTCP | `event_tcp.go` | StartNS, EndNS, PID, LAddr/RAddr, LPort/RPort, Rx/Tx, Flags |
| `EventIPV4` | EBPFProbeKTCPSec | `event_ktcp_sec.go` | TSUS, PID, UID, AF, LAddr/RAddr, LPort/RPort, TASK |
| `EventIPV6` | EBPFProbeKTCPSec | `event_ktcp_sec.go` | TSUS, PID, UID, AF, RAddr[16], RPort, TASK |
| `EventOther` | EBPFProbeKTCPSec | `event_ktcp_sec.go` | TSUS, PID, UID, AF, TASK |
| `UDPEvent` | EBPFProbeKUDP | `event_kudp.go` | pid, comm, DNS 问题列表/答案列表（通过 rawdns 解析） |
| `DNSEVENT` | EBPFProbeUDNS | `event_udns.go` | PID, UID, AF, AddrIpv4, AddrIpv6[16], HOST[80] |
| `JavaJDKExecPeEvent` | EBPFProbeUJavaRASP | `event_java_rasp.go` | Pid, Mode, File[128] |
| `ForkProcEvent` | EBPFProbeProc | `event_proc.go` | Child/Parent/GrandParent PID & TGID, UID, Gid, Comm, Cmdline, Path |
| `BpfCallEvent` | EBPFProbeBPFCall | `event_bpf_call.go` | Type(BPFCmd), 三级进程链 PID/TGID, UID/GID, Comm, Cmdline, UtsName |

### 8.2 Decode 实现规范

所有结构体的 `Decode` 方法使用 `encoding/binary.Read` 按小端序读取，字段顺序与内核 C 结构体中的字段声明顺序完全一致，例：

```go
func (e *TCPEvent) Decode(payload []byte) (err error) {
    buf := bytes.NewBuffer(payload)
    binary.Read(buf, binary.LittleEndian, &e.StartNS)
    binary.Read(buf, binary.LittleEndian, &e.EndNS)
    binary.Read(buf, binary.LittleEndian, &e.PID)
    // ... 其余字段按序读取
    return nil
}
```

`BpfCallEvent` 是特例，直接使用字节切片偏移量读取（因 tracepoint 的 raw args 布局固定）。

---

## 9. 内核态 eBPF 程序设计

### 9.1 头文件组织

```
kern/ehids_agent.h          ← 所有 .c 文件统一 include 的入口头
    ├── kern/vmlinux.h       ← 由 BTF 生成的内核数据结构定义（CO-RE 模式）
    ├── kern/bpf/bpf_helpers.h    ← eBPF helper 函数声明
    ├── kern/bpf/bpf_tracing.h   ← kprobe/uprobe 辅助宏
    ├── kern/bpf/bpf_core_read.h ← CO-RE 读取宏
    └── kern/common.h        ← 自定义公共宏与事件结构体
```

### 9.2 BPF Map 类型选择

| Map 类型 | 使用场景 | 说明 |
|----------|----------|------|
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | 网络、安全、BPF 调用事件 | 高吞吐量，每 CPU 独立 buffer，支持丢包检测 |
| `BPF_MAP_TYPE_RINGBUF` | 进程创建事件 | 内核 5.8+ 新特性，全局共享 buffer，更节省内存 |
| `BPF_MAP_TYPE_HASH` | TCP 连接状态跟踪 | 在 `tcp_set_state` entry 保存 conn 信息，在特定状态转换时读取 |

### 9.3 编译构建流程

```
kern/*.c
    │
    └─ clang -O2 -target bpf -D__TARGET_ARCH_x86 \
             -I kern/ -I kern/bpf/ \
             -c <file>_kern.c -o user/bytecode/<file>_kern.o
                │
                └─ go-bindata -pkg assets \
                              user/bytecode/*.o
                              → assets/ebpf_probe.go
                                    │
                                    └─ go build → bin/ehids-agent
```

**CO-RE 支持：** 编译时通过 `-DCORE` 宏开关，决定是否使用 `vmlinux.h` + `bpf_core_read.h` 实现跨内核版本兼容。

---

## 10. 数据流程

### 10.1 完整事件处理流程

```
内核事件触发（如 tcp_set_state 被调用）
    │
    ▼
eBPF kprobe/uprobe/tracepoint 程序执行
    │
    ├─ 从内核数据结构中读取字段（使用 BPF helper / CO-RE）
    ├─ 填充自定义事件结构体
    └─ bpf_perf_event_output() 或 bpf_ringbuf_submit() 写入 Map
         │
         ▼
    BPF Map（内核内存）
         │
         ▼  （Go 调用 rd.Read() 从 Map 读取）
    perf.Record.RawSample 或 ringbuf.Record.RawSample
         │
         ▼
    child.Decode(em, rawBytes)
         │
         └─ child.DecodeFun(em) → 找到对应的 IEventStruct 实现
               │
               ├─ es.Clone()    → 创建新实例，避免并发冲突
               └─ es.Decode()   → binary.Read 逐字段解析
                      │
                      ▼
               es.String()  → 格式化为可读字符串
                      │
                      ▼
               Module.Write() → logger.Println(...)
```

### 10.2 优雅关闭流程

```
收到 SIGTERM 或 SIGINT
    │
    ▼
main.go: cancelFun()  → ctx.Done() channel 关闭
    │
    ├─ readEvents() 中的 select case <-ctx.Done() 触发 → return nil
    │
    └─ run() goroutine 中的 select case <-ctx.Done() 触发
            │
            └─ child.Close()
                    └─ bpfManager.Stop(CleanAll)
                            ├─ 卸载 eBPF 程序（detach kprobe/uprobe）
                            └─ 关闭 BPF Map fd
                                    └─ rd.Read() 返回 ErrClosed → 事件循环退出
```

---

## 11. 新增探针开发指南

开发者只需实现以下 **三个文件** 即可接入框架：

### 步骤一：编写内核态 eBPF C 程序

**文件**：`kern/<name>_kern.c`

```c
// 引入统一头文件
#include "ehids_agent.h"

// 定义事件结构体（需与用户态 Go 结构体字段顺序完全一致）
struct my_event_t {
    __u32 pid;
    char comm[16];
    // ...
};

// 定义 BPF Map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} my_events SEC(".maps");

// 实现 eBPF 程序
SEC("kprobe/<kernel_function>")
int kprobe__my_function(struct pt_regs *ctx) {
    struct my_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // 填充其他字段 ...
    bpf_perf_event_output(ctx, &my_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}
```

### 步骤二：实现用户态事件结构体

**文件**：`user/event_<name>.go`

```go
package user

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

type MyEvent struct {
    PID  uint32
    Comm [16]byte
    // ... 字段顺序必须与内核 C 结构体完全一致
}

func (e *MyEvent) Decode(payload []byte) (err error) {
    buf := bytes.NewBuffer(payload)
    if err = binary.Read(buf, binary.LittleEndian, &e.PID); err != nil {
        return
    }
    if err = binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
        return
    }
    return nil
}

func (e *MyEvent) String() string {
    return fmt.Sprintf("PID:%d, Comm:%s", e.PID, e.Comm)
}

func (e *MyEvent) Clone() IEventStruct {
    return new(MyEvent)
}
```

### 步骤三：实现用户态探针模块

**文件**：`user/probe_<name>.go`

```go
package user

import (
    "bytes"
    "context"
    "ehids/assets"
    "github.com/cilium/ebpf"
    manager "github.com/ehids/ebpfmanager"
    "github.com/pkg/errors"
    "golang.org/x/sys/unix"
    "log"
    "math"
)

type MMyProbe struct {
    Module
    bpfManager        *manager.Manager
    bpfManagerOptions manager.Options
    eventFuncMaps     map[*ebpf.Map]IEventStruct
    eventMaps         []*ebpf.Map
}

func (this *MMyProbe) Init(ctx context.Context, logger *log.Logger) error {
    if err := this.Module.Init(ctx, logger); err != nil {
        return err
    }
    this.Module.SetChild(this)
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
    return nil
}

func (this *MMyProbe) Start() error {
    return this.start()
}

func (this *MMyProbe) start() error {
    buf, err := assets.Asset("user/bytecode/<name>_kern.o")
    if err != nil {
        return errors.Wrap(err, "couldn't find asset")
    }
    this.setupManagers()
    if err = this.bpfManager.InitWithOptions(bytes.NewReader(buf), this.bpfManagerOptions); err != nil {
        return errors.Wrap(err, "couldn't init manager")
    }
    if err = this.bpfManager.Start(); err != nil {
        return errors.Wrap(err, "couldn't start manager")
    }
    return this.initDecodeFun()
}

func (this *MMyProbe) Close() error {
    if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
        return errors.Wrap(err, "couldn't stop manager")
    }
    return nil
}

func (this *MMyProbe) setupManagers() {
    this.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "kprobe/<kernel_function>",
                EbpfFuncName:     "kprobe__my_function",
                AttachToFuncName: "<kernel_function>",
            },
        },
        Maps: []*manager.Map{{Name: "my_events"}},
    }
    this.bpfManagerOptions = manager.Options{
        DefaultKProbeMaxActive: 512,
        VerifierOptions: ebpf.CollectionOptions{
            Programs: ebpf.ProgramOptions{LogSize: 2097152},
        },
        RLimit: &unix.Rlimit{Cur: math.MaxUint64, Max: math.MaxUint64},
    }
}

func (this *MMyProbe) initDecodeFun() error {
    m, found, err := this.bpfManager.GetMap("my_events")
    if err != nil {
        return err
    }
    if !found {
        return errors.New("cant found map:my_events")
    }
    this.eventMaps = append(this.eventMaps, m)
    this.eventFuncMaps[m] = &MyEvent{}
    return nil
}

func (this *MMyProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
    fun, found := this.eventFuncMaps[em]
    return fun, found
}

func (this *MMyProbe) Events() []*ebpf.Map {
    return this.eventMaps
}

// init 函数在包加载时自动注册，无需修改任何现有文件
func init() {
    mod := &MMyProbe{}
    mod.name = "EBPFProbeMyName"
    mod.mType = PROBE_TYPE_KPROBE
    Register(mod)
}
```

### 步骤四：更新 Makefile

在 `Makefile` 的 `ebpf` target 中添加新 C 文件的编译规则：

```makefile
$(CLANG) $(CFLAGS) -c kern/<name>_kern.c -o user/bytecode/<name>_kern.o
```

然后重新执行 `make` 即可，框架会自动加载并运行新探针。

---

## 12. 技术选型与依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `github.com/cilium/ebpf` | v0.8.1 | 核心 eBPF 库：Map 操作、perf/ringbuf reader、rlimit |
| `github.com/ehids/ebpfmanager` | v0.2.2 | 上层封装：eBPF 程序生命周期管理、PerfMap 回调 |
| `github.com/cirocosta/rawdns` | v0.0.0 | DNS 报文解析（用于 UDP 探针） |
| `github.com/pkg/errors` | v0.9.1 | 错误包装与上下文追加 |
| `github.com/shuLhan/go-bindata` | v4.0.0 | 将 eBPF .o 文件嵌入 Go 二进制 |
| `golang.org/x/sys` | latest | Linux 系统调用封装（unix.Rlimit 等） |
| `clang/LLVM` | ≥ 9 | eBPF C 代码编译器 |
| `Go` | ≥ 1.16 | 用户态编译器 |

**探针类型常量（`user/common.go`）：**

```go
const (
    PROBE_TYPE_UPROBE = "uprobe"
    PROBE_TYPE_KPROBE = "kprobe"
    PROBE_TYPE_TP     = "tracepoint"
    PROBE_TYPE_XDP    = "XDP"      // 预留，当前未使用
)
```

---

## 13. 编译与运行

### 环境要求

| 组件 | 版本要求 |
|------|----------|
| OS | Ubuntu 21.04 或兼容 Linux 发行版 |
| Linux 内核 | ≥ 4.15（RingBuf 需 ≥ 5.8） |
| Go | ≥ 1.16 |
| clang/LLVM | ≥ 9 |

### 编译步骤

```shell
# 安装系统依赖
sudo apt-get install -y make gcc clang llvm libelf-dev

# 克隆并编译
git clone https://github.com/ehids/ehids-agent.git
cd ehids-agent

# 完整编译（eBPF C → 字节码 → 嵌入 → Go 二进制）
make all

# 或仅重新编译 Go 部分（字节码已存在）
make build
```

### 运行

```shell
# 需要 root 权限或 CAP_BPF + CAP_SYS_ADMIN 能力
sudo ./bin/ehids-agent
```

### Makefile 主要目标

| 目标 | 说明 |
|------|------|
| `make all` | 完整构建（eBPF + assets + Go） |
| `make ebpf` | 仅编译 eBPF C 代码 |
| `make assets` | 仅重新生成 go-bindata 资源文件 |
| `make build` | 仅编译 Go 二进制 |
| `make nocore` | 编译非 CO-RE 版本（不依赖 BTF） |
| `make clean` | 清理所有构建产物 |
| `make env` | 打印当前编译环境信息 |
