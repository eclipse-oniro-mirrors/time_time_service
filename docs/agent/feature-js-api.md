# feature-js-api.md — 多语言 API 框架与客户端领域知识

> 本文档为 Agent 知识路由目标，由根 AGENTS.md 的 task-based / path-based / vocabulary-based routing 触发阅读。
> Agent 能自己探索出来的少写；Agent 猜不准、猜错代价高、团队必须统一执行的内容要写。

## 1. Where to look

| 任务类型 | 先看哪里 |
|---|---|
| NAPI 接口（systemDateTime/systemTime/systemTimer） | `framework/js/napi/<module>/src/*.cpp` |
| NAPI 异步工作模式 | `framework/js/napi/common/src/napi_work.cpp` |
| ANI 轻量层 | `framework/js/ani/src/system_date_time_ani.cpp` |
| Taihe（IDL 生成层） | `framework/js/taihe/<module>/idl/*.taihe`（接口定义）+ `src/*.impl.cpp`（手写实现） |
| C API（NDK） | `interfaces/kits/c/` |
| 仓颉绑定 | `framework/cj/` |
| inner_api 客户端 | `interfaces/inner_api/src/time_service_client.cpp` |
| 定时器到期回调链 | `services/time/src/timer_call_back.cpp` |
| 共享时间工具 | `framework/js/common/src/time_gettime_utils.cpp` |

## 2. 五个语言面总览

同一服务能力暴露给五种调用方，各层注册入口与产物：

| 层 | 注册入口 | 产物 | 面向 |
|---|---|---|---|
| NAPI | `__attribute__((constructor))` + `napi_module_register`（各 `*_init.cpp`） | `libsystemdatetime.z.so` / `libsystemtime.z.so` / `libsystemtimer.z.so` | 应用 JS |
| ANI | `ANI_EXPORT ANI_Constructor` + `Namespace_BindNativeFunctions` | `libsystemdatetime_ani.so` + `.abc` | ArkTS 直调（性能优化层） |
| Taihe | `ANI_Constructor` → 生成的 `ANIRegister` | `libsystemdatetime_taihe_native.z.so` / `libsystemtimer_taihe_native.z.so` | ArkTS（新一代主力） |
| C API | 无（直接函数调用） | `libtime_service_ndk.so` | native 应用 |
| 仓颉 | FFI（`FFI_EXPORT`） | `libcj_system_date_time_ffi.so` | 仓颉应用 |

**能力差异矩阵**（新增 API 时先决定铺到哪些层）：

| 能力 | napi systemTime（旧） | napi systemDateTime | ANI | Taihe | C API | CJ |
|---|---|---|---|---|---|---|
| setTime/setTimezone | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| setDate/getDate | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| getTime/getUptime/NTP/自动同步 | ❌ | ✅ | 部分（仅 getTime） | ✅ | ❌ | 部分（getTime/getUptime，无 NTP/自动同步） |
| getTimezone（查询） | ✅ | ✅ | ✅（getTimezoneSync） | ✅ | ✅（唯一能力） | ✅ |
| Timer 四件套 | ✅ | — | — | ✅ | ❌ | ❌ |
| Sync 同步变体 | ❌ | 仅 getTimezoneSync | ✅ | ✅（全 API） | —（本就同步） | — |

关键事实：
- **ANI 层是刻意做小的**：只绑定 `getTime` 与 `getTimezoneSync` 两个高频只读 API（直读时钟，不走 IPC），不是漏写——不要"顺手补全"。
- `@ohos.systemTime`（NAPI 旧模块）已停止维护，README 声明推荐 `@ohos.systemDateTime`；新能力不应加入旧模块。
- C API `OH_TimeService_GetTimeZone` 直接 `GetParameter("persist.time.timezone")` 读系统参数，**不走 SA IPC**——行为与 SA 无关，改 SA 侧时区逻辑不影响它。

## 3. Taihe 生成机制（改错文件会白干）

```
framework/js/taihe/system_datetime/
├── idl/ohos.time_service.systemDateTime.taihe   ← 接口定义（手写，改 API 先改这里）
└── src/
    ├── ohos.time_service.systemDateTime.impl.cpp  ← 手写业务实现（入仓）
    ├── ani_constructor.cpp                        ← 手写注册入口（入仓）
    └── …（生成的 .ani.cpp/.abi.c/.proj.hpp/.impl.hpp 不入仓，编译期产出）
```

- BUILD.gn 链：`copy_taihe_idl` → `ohos_taihe("run_taihe")`（调 IDL 编译器生成胶水）→ `taihe_shared_library`（生成物 + 手写 impl.cpp 组装）→ `generate_static_abc` → 安装 `.abc` 到 `/system/framework/`。
- **只改 `.taihe` 与 `*.impl.cpp`**；生成的 `.ani.cpp`/`.abi.c`/`.proj.hpp`/`.impl.hpp` 是编译期产物，手改会被覆盖。
- IDL 注解语义：`@!namespace("@ohos.xxx", "so名")`、`@async`/`@promise` 生成三变体（Async/Promise/Sync）、`@!sts_inject(loadLibraryWithPermissionCheck(...))` 注入加载期权限检查。
- 服务侧 IDL 同理：`services/ITimeService.idl` + `ITimerCallback.idl` 经 `idl_gen_interface` 生成 proxy/stub，生成物按 `*service_proxy.cpp`/`*callback_stub.cpp`（→ `timeservice_proxy`，客户端用）与 `*service_stub.cpp`/`*callback_proxy.cpp`（→ `time_system_ability`，服务端用）分流。

## 4. inner_api 客户端（TimeServiceClient）

- 单例（`GetInstance` 双检锁，`instance_` 用 `__attribute__((no_destroy))` 标注防析构顺序问题），构造即 `ConnectService`。
- 连接：`GetSystemAbility(3702)` → 死亡检测 → `AddDeathRecipient`（死亡时 `ClearProxy`）→ `iface_cast` 得 proxy → `SubscribeSA` 订阅上下线。
- **SA 重启自愈**：`TimeServiceListener::OnAddSystemAbility` 重连后遍历 `recoverTimerInfoMap_`，逐个 `CreateTimer`（state==1 的再 `StartTimer`）——应用无感知地恢复定时器。新建定时器都会 `RecordRecoverTimerInfoMap` 登记到恢复表；`NotifyTimer` 触发后 `HandleRecoverMap` 清理。

### 定时器到期回调链（完整）

```
SA TimerLooper 触发
  → ITimerCallback Proxy（IPC，客户端进程）
  → TimerCallback::NotifyTimer(timerId)          services/time/src/timer_call_back.cpp
  → 查 timerInfoMap_（disposable 则立即移除）
  → ITimerInfo::OnTrigger()
  → napi 层: napi_send_event → napi_call_function → JS callback
    taihe 层: std::function 直接调用
```

`TimerCallback` 是客户端进程内的 IPC stub，其 `AsObject()` 在 `CreateTimer` 时传给 SA 持有。`ITimerInfo`（`interfaces/inner_api/include/itimer_info.h`）是应用侧回调接口：`SetType/SetRepeat/SetInterval/SetWantAgent` 虚函数 + `OnTrigger` 纯虚。

## 5. 构建配置与编译开关

- `bundle.json`：部件 `time_service`，子系统 `time`，syscap `SystemCapability.MiscServices.Time`。
- `time.gni` 定义编译开关（`declare_args` 默认值，bundle.json features 可覆盖）：

| 开关 | 默认 | 控制 |
|---|---|---|
| `time_service_rdb_enable` | true | 定时器 RDB 持久化（关则 CJSON 降级） |
| `time_service_multi_account` | true | 多用户清理/校验 |
| `time_service_debug_able` | true | 调试日志 |
| `time_service_hidumper_able` | true | hidumper 支持 |
| `time_service_time_rand_enable` | true | `TIME_GETTIME_RANDOM`（见 §6） |
| `time_service_running_lock_optimize` | false | 运行锁优化 |
| `time_service_set_auto_reboot` | false | 关机闹钟 |
| `time_service_callback_autoboot_enable` | false | 关机闹钟回调式实现 |

服务侧宏（`RDB_ENABLE`/`MULTI_ACCOUNT_ENABLE` 等）由上述开关映射，语义见 `docs/agent/feature-timer.md` §6。

## 6. 共享工具与防时间回退

`framework/js/common/` 的 `GetMonotoneWallTimeNs()` 仅在 `TIME_GETTIME_RANDOM` 宏（`time_service_time_rand_enable`，默认 true）下编译：提供单调递增的 CLOCK_REALTIME 纳秒时间戳，被 ANI/NAPI/Taihe 三层的 getTime 类接口引用，用于防止时间回退攻击（攻击者回拨系统时间影响随机数/超时逻辑）。改动时保持三层一致引用。

## 7. NAPI 异步工作模式

新写 NAPI 方法遵循既有模式（`framework/js/napi/common/src/napi_work.cpp`）：
- 继承 `ContextBase` 的局部上下文结构体；`GetCbInfo` 自动识别末尾 function 参数（AsyncCallback）或走 Promise。
- `execute` lambda（子线程）调 `TimeServiceClient`；`complete` lambda（主线程）组装输出。
- `AsyncEnqueue` 用 `napi_queue_async_work_with_qos(..., napi_qos_user_initiated)`；同步版本 `SyncEnqueue` 直接执行并 `napi_throw`。

## 8. 测试结构

| 目录 | 框架 | 目标 |
|---|---|---|
| `test/unittest/service_test/` | gtest（`HWTEST_F`） | `TimeClientTest`、`TimeDfxTest`、`TimeGettimeUtilsTest`、`TimePermissionTest`、`TimeProxyTest`、`TimeServiceTimeTest`、`TimeServiceTimerTest`、`TimeServiceBasicTest`、`TimerAppStateObserverTest`、`TimerDatabaseTest`、`TimerLockOptimizerTest` |
| `test/unittest/js_test/` | hypium（HAP） | `TimeTestWithPermission`（带 SET_TIME/SET_TIME_ZONE）、`TimeTestNoAclPermission`、无权限 systemapi 组 |
| `test/unittest/native_test/` | gtest | `TimeServiceNativeTest`（C API） |
| `test/fuzztest/` | libfuzzer | 客户端 API、IPC 入口、TimerProxy、SNTP 等 28 个 fuzzer |

**service_test 的 mock 方式**（沿用，勿引入 gmock）：
- `#define private public` / `#define protected public` 暴露私有成员（见 `test/unittest/service_test/src/time_service_time_test.cpp` 头部）
- 静态链接 `time_system_ability_static`（`services/BUILD.gn` 的 `ohos_static_library`）直测 SA 实现，不走 IPC
- `nativetoken_kit` + `token_setproc` 注入系统权限 token
- `TimePermission::SetAuthorizationClient`/`ResetAuthorizationClient` 注入 mock 授权客户端

## 9. 硬约束

### 禁止事项

- NEVER 手改 Taihe/IDL 生成的文件（`.ani.cpp`/`.abi.c`/`.proj.hpp`/`.impl.hpp`），改 `.taihe` 或 `.idl` 后重新生成。
- NEVER 向 `@ohos.systemTime`（NAPI 旧模块）新增 API——已停止维护。
- NEVER 变更 `services/*.idl` 方法顺序（接口码二进制兼容，见 feature-time.md §3）。
- NEVER 在 NAPI `execute` lambda（子线程）中调用任何 napi_* JS 交互 API（只能在 complete 中做）。

### 必须先问人

- 新增公共 API（需确认铺到哪些语言面、API 版本、权限声明）。
- 变更 `bundle.json` 编译开关默认值（影响整机产品构建）。
- 变更 inner_api 导出头（`interfaces/inner_api/include/`，`innerapi_tags=["platformsdk","sasdk"]`，下游依赖）。

### 易错点

- 新增 Taihe API 时三处都要动：`.taihe` 定义、`.impl.cpp` 实现、（若有回调）IDL 类型；只改 impl 不会有新接口。
- js_test 的 HAP 权限由 `test/unittest/js_test/permission/config.json` 声明，漏声明导致用例误报"无权限"。
- `TimeServiceClient` 的 `recoverTimerInfoMap_` 只增不清会导致 SA 重启后重复恢复；销毁路径走 `HandleRecoverMap`，改 DestroyTimer 链路时验证它。
