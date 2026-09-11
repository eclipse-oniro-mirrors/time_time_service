# feature-timer.md — 定时器领域知识

> 本文档为 Agent 知识路由目标，由根 AGENTS.md 的 task-based / path-based / vocabulary-based routing 触发阅读。
> Agent 能自己探索出来的少写；Agent 猜不准、猜错代价高、团队必须统一执行的内容要写。

## 1. Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 定时器生命周期（创建/启动/停止/销毁） | `services/timer/src/timer_manager.cpp` |
| 调度循环 / 内核定时器交互 | `services/timer/src/timer_manager.cpp`（`TimerLooper`）+ `services/timer/src/timer_handler.cpp` |
| 批量合并（batch） | `services/timer/src/batch.cpp` + `services/timer/src/timer_manager.cpp`（`AttemptCoalesceLocked`） |
| 持久化（RDB） | `services/timer/src/timer_database.cpp`（表结构/升级/损坏恢复） |
| 持久化（CJSON 降级） | `services/timer/src/cjson_helper.cpp` |
| 数据库巡检 DFX | `services/timer/src/timer_database_monitor.cpp` |
| 代理/调整（proxy/adjust） | `services/timer/src/timer_proxy.cpp` |
| 运行锁优化 | `services/timer/src/timer_lock_optimizer.cpp` + `services/timer/src/timer_app_state_observer.cpp` |
| 重启恢复 | `services/time_system_ability.cpp`（`RecoverTimer`/`RecoverTimerFromDb`/`RecoverTimerCjson`） |
| IPC 入口与权限 | `services/time_system_ability.cpp`（CreateTimer/StartTimer/StopTimer/DestroyTimer 等） |
| 定时器结构体 | `services/timer/include/timer_info.h`（`TimerInfo`）+ `interfaces/inner_api/include/itimer_info.h` |

入口行号锚点（`services/timer/src/timer_manager.cpp`）：`CreateTimer` :256、`ReCreateTimer` :313、`StartTimer` :339、`StopTimer` :494、`DestroyTimer` :499、`TimerLooper` :729、`AdjustTimer` :1326、`ProxyTimer` :1358、`ResetAllProxy` :1421。

## 2. 架构与线程模型

```
IPC 线程                                  timer_loop 线程（TimerManager 专属）
CreateTimer/StartTimer/...               TimerLooper: WaitForAlarm(epoll)
    │ entryMapMutex_                         │ mutex_
    ▼                                        ▼
timerEntryMap_（全部定时器条目）          alarmBatches_（Batch 列表）──► TimerHandler（timerfd + epoll）
    │                                        │
    ▼                                        ▼
TimerDatabase（SQLite 持久化）            DeliverTimersLocked（锁外投递）
                                           ├─► ITimerCallback Proxy ──► 应用回调
                                           ├─► WantAgent 通知
                                           └─► RunningLock（wakeup 场景）
```

- **`timerEntryMap_` vs `alarmBatches_`**：前者是全部已创建定时器的注册表（含未启动的），后者是已排入调度（已 Start）的定时器按时间分批的视图。两套数据两把锁。
- **`TimerLooper`** 是唯一操作 `alarmBatches_` 与内核 timerfd 的线程（`pthread_setname_np "timer_loop"`）。循环：`WaitForAlarm` → 时间变更处理（`ReBatchAllTimers`）→ `TriggerTimersLocked` → `DeliverTimersLocked` → `RescheduleKernelTimerLocked`。
- `DeliverTimersLocked` 刻意在 `mutex_` **之外**执行：投递会触发 PowerManager 申请 RunningLock，PowerManager 可能回调 TimeService 接口，持锁投递会死锁（`timer_manager.cpp` 注释）。

### 锁顺序（不可反序）

1. `TimerManager`：`entryMapMutex_` → `mutex_`（`StartTimer` 中先锁 entryMap 再锁 batch）
2. `TimerProxy`：`proxyMutex_` → `uidTimersMutex_`（`timer_proxy.h` 注释）；`adjustMutex_` 独立
3. `TimeTickNotify::timerId_` 必须用 atomic 而非锁（见 `docs/agent/feature-time.md` §2.5 死锁说明）

### TimerHandler（timerfd/epoll 封装）

- 每种时钟一个 timerfd，由 epoll 统一等待：`CLOCK_REALTIME_ALARM`、`CLOCK_REALTIME`、`CLOCK_BOOTTIME_ALARM`、`CLOCK_BOOTTIME`、`CLOCK_MONOTONIC` 等（`alarm_to_clock_id` 数组）；`SET_AUTO_REBOOT_ENABLE` 下额外有 `CLOCK_POWEROFF_ALARM`(12)。
- `WaitForAlarm` 返回 bitmask，每 bit 对应一种 fd。
- **`CLOCK_REALTIME` fd 返回 `ECANCELED` = 系统时间被修改**（`ALARM_TIME_CHANGE_MASK`），触发 `ReBatchAllTimers` 重排所有 REALTIME 定时器——这是"改系统时间后定时器跟随调整"的机制。

## 3. 生命周期语义

- **CreateTimer**：随机生成 timerId（冲突重试上限 100 次）；构造 `TimerEntry` 入 `timerEntryMap_`；同 uid 同 name 的新定时器**替换**旧定时器（旧的被销毁）；带 WantAgent 的定时器按 `CheckNeedRecoverOnReboot` 写 `hold_on_reboot` 或 `drop_on_reboot` 表。
- **StartTimer**：构造 `TimerInfo` → `RemoveLocked`（先移除旧调度）→ `SetHandlerLocked`（考虑 proxy/idle 后 `InsertAndBatchTimerLocked` + `RescheduleKernelTimerLocked`）→ 更新数据库 state=1。
- **StopTimer**：移出 batch，state=0，条目保留（可再次 Start）。
- **DestroyTimer**：移出 batch + 从 `timerEntryMap_` 删除 + 计数递减 + 删数据库记录。`DestroyTimerAsync`（IDL `[oneway]`）当前实现为直接调用同步 `DestroyTimer`。
- **ReCreateTimer**（恢复路径）：`insert` 返回值检查重复，已存在直接返回，避免覆盖与计数错误。
- **定时器类型**（`itimer_info.h`）：`TIMER_TYPE_REALTIME`(1)、`WAKEUP`(2)、`EXACT`(4)、`IDLE`(8)、`TIMER_TYPE_INEXACT_REMINDER`(16)。REALTIME 基于墙钟（改时间影响），ELAPSED 基于开机时间（重启后失效）。
- **WantAgent 投递失败重试**：`NotifyWantAgentRetry` 在 detached 线程中最多重试 6 次。

### Batch 合并

时间窗口重叠的定时器合并为一批共享一次内核唤醒（`AttemptCoalesceLocked` + `batch.cpp` `CanHold`），STANDALONE flag 的定时器不参与合并。batch 列表按 start 时间排序。修改合并逻辑影响功耗指标，需谨慎。

## 4. 持久化

**RDB 模式**（默认，`time_service_rdb_enable=true`）：
- SQLite 路径 `/data/service/el1/public/database/time/time.db`，SecurityLevel S1，不加密
- 两张表：`hold_on_reboot`（autoRestore，重启后恢复）与 `drop_on_reboot`（重启后丢弃）
- 列：`timerId(PK), type, flag, windowLength, interval, uid, bundleName, wantAgent, state, triggerTime, pid, name`；数据库版本 3（v2 加 `pid` 列，v3 加 `name` 列）
- **改表结构必须同步三处**：`timer_database.h` 的 `COLUMN_INDEX_*` 常量、`time_system_ability.cpp` 与 `timer_manager.cpp` 各自的 `ALL_DATA` 列名向量——`COLUMN_INDEX_*` 与表列顺序强耦合
- `OnDowngrade` 直接返回 `E_OK` 不删列（降级不迁移）
- **损坏自愈**：写路径遇 `E_SQLITE_CORRUPT` 时 `RecoverDataBase` 用 `inFlightCv_` 等 in-flight 操作结束后 `DeleteRdbStore` 删库重建；`StoreGuard` RAII 管理 in-flight 引用计数，`WrapResult` 把计数绑定到 ResultSet 生命周期
- **巡检**：`TimerDatabaseMonitor` 后台线程每 12h 检查库大小，超 5MB 基线先 `CheckpointWal` 再上报 `TIMER_DATABASE_OVER_BASELINE_REPORT`（含 Top10 应用）

**CJSON 模式**（`RDB_ENABLE` 关闭时的降级路径，跨平台场景）：文件 `/data/service/el1/public/database/time/time.json`。RDB 模式启动时 `CjsonIntoDatabase` 把旧 JSON 数据迁入数据库后清空。

**重启恢复**：`OnAddSystemAbility`/`OnStart` 触发 `RecoverTimer` → 读表 → `ReCreateTimer` + state=1 的 `StartTimer`。恢复路径与 binder 回调线程中的 TimerManager 内部调用**不走 IPC 入口校验**，直接调 `TimerManager::GetInstance()`。

**清理规则**（`ClearInvaildDataInHoldOnReboot`）：`state=0`、`type=2`(ELAPSED_REALTIME_WAKEUP)、`type=3`(ELAPSED_REALTIME) 的记录删除——ELAPSED 类型基于 boot time，重启后无意义。

## 5. 代理与调整（系统场景专用）

- **ProxyTimer**（`timer_proxy.cpp`）：设备休眠/冻结等场景由 RSS 调用，将指定 uid/pid 的定时器统一延迟 `proxyDelayTime_`（3 天）；`ResetAllProxy` 恢复。
- **AdjustTimer / SetAdjustPolicy**：省电模式下按策略调整定时器触发频率。
- **SetTimerExemption**：豁免指定 name 的定时器不被代理/调整。
- 权限：这组接口仅放行 `TOKEN_NATIVE`/`TOKEN_SHELL`（`CheckProxyCallingPermission`），应用不可调用。

## 6. 电源与多用户（编译宏门控）

| 宏 | 能力 | 注意 |
|---|---|---|
| `POWER_MANAGER_ENABLE` | wakeup 定时器触发前若下次唤醒在 2s 内持 RunningLock 防休眠 | 默认持锁 1s（`persist.time.running_lock_duration` 可调） |
| `RUNNING_LOCK_OPTIMIZE` | `TimerLockOptimizer` 按应用运行状态缩短持锁：目标应用已运行则缩短，冷启动 Ability 场景持 10s | 依赖 `TimerAppStateObserver` 注册 AppMgr；批量触发时合并取最大 expire time 一次申请 |
| `SET_AUTO_REBOOT_ENABLE` | 关机闹钟：`OnSyncShutdown` 清理无效数据，`ArmPowerOffTimer` 用 `CLOCK_POWEROFF_ALARM` timerfd | **`itimerspec` 必须值初始化 `{}`** 使 `it_interval=0`，否则变成重复关机闹钟（代码注释）；触发时间 <2min 强制延迟到 2min 后 |
| `CALLBACK_AUTOBOOT_ENABLE` | 关机闹钟走回调而非 timerfd | 与上行互斥的两种实现 |
| `MULTI_ACCOUNT_ENABLE` | `OnUserRemoved` 清理对应用户定时器；投递前 `CheckUserIdForNotify` | |
| `DEVICE_STANDBY_ENABLE` | 设备空闲时非豁免定时器延迟（`AdjustDeliveryTimeBasedOnDeviceIdle`）；`IDLE_UNTIL` 定时器挂起其他全部定时器 | 依赖 device_standby 部件存在性 |

宏开关定义在 `time.gni`（默认值）与 `bundle.json` features（部件级覆盖），见 `docs/agent/feature-js-api.md` §5。

## 7. 权限与安全

- `CreateTimer`/`StartTimer`/`StopTimer`/`DestroyTimer`：仅 `CheckSystemUidCallingPermission`（系统应用或 native/shell）。**注意确认当前代码是否校验 timerId 归属 uid**——历史上该入口曾长期只判调用方身份、不判 timerId 归属（知道 timerId 的任意系统应用可操作他方定时器）；若你的任务涉及这块校验，先 grep `GetTimerOwnerUid` 确认现状，补充校验时注意 binder 回调线程上的恢复路径（`OnAddSystemAbility`/`OnPackageRemoved`/`OnUserRemoved`）不能被入口校验拦截。
- 定时器数量按 uid 计数（`timerCount_`），`ALARM_COUNT` 打点含 Top5 UID，用于异常应用治理。
- 日志降噪：`NO_LOG_APP_LIST`（`wifi_manager_service`、`telephony`）的高频非唤醒定时器不打印日志；timerId 在日志中截断为最多 5 位（`TruncateTimerId`）。

## 8. 硬约束

### 禁止事项

- NEVER 反序获取锁（`entryMapMutex_`→`mutex_`；`proxyMutex_`→`uidTimersMutex_`）——已有代码依赖该顺序，反序死锁。
- NEVER 在持有 `mutex_` 时执行投递/回调（WantAgent、RunningLock、PowerManager 交互必须在锁外，见 §2）。
- NEVER 改表列顺序而不同步 `COLUMN_INDEX_*` 与两处 `ALL_DATA` 向量。
- NEVER 在非 `RDB_ENABLE` 构建上引用 `timer_database.h`（该头本身在宏内 include）。
- NEVER 删除 `StoreGuard`/`WrapResult` 的引用计数逻辑（损坏恢复依赖它等待 in-flight 操作）。

### 必须先问人

- 变更 `hold_on_reboot`/`drop_on_reboot` 表结构或数据库版本号（涉及升级迁移）。
- 变更 Batch 合并策略（功耗与精度的权衡）。
- 变更 proxy 延迟时长（3 天）或 adjust 策略默认值。
- 新增/变更 IPC 接口（IDL 变更，见 feature-time.md §3）。

### 易错点

- 改 `time.gni` 开关后必须全量重编 `time_system_ability` 与测试，条件编译分支多（本文件 §6 的宏表），漏改宏会出现"某构建下编不过"。
- 关机闹钟路径的 `itimerspec new_value {}` 值初始化不能省（§6）。
- `StartTimer` 对已启动的定时器是"先移除再插入"，不是幂等 no-op；依赖旧触发的行为会变。
- 同 uid 同 name 创建新定时器会隐式销毁旧定时器——应用侧常用它做"更新"，但服务侧改动 `AddTimerName` 时要保持该语义。

## 9. 验证

> 通用构建/lint/Done 定义见根 AGENTS.md §4。

- 定时器生命周期变更：跑 `TimeServiceTimerTest`（`test/unittest/service_test/src/time_service_timer_test.cpp`）。
- 持久化变更：跑 `TimerDatabaseTest`；RDB/CJSON 双模式都要考虑（`time_service_rdb_enable=false` 的降级编译）。
- 代理/调整：跑 `TimeProxyTest`；锁优化跑 `TimerLockOptimizerTest`。
- 设备侧诊断：`hdc shell hidumper -s 3702 -a "-timer -a"`（全部）、`-timer -i <id>`、`-ProxyTimer -l`、`-UidTimer -l`、`-adjust -a`。
- 历史遗留：数据库损坏恢复分支与 TimerLooper 核心路径无 UT 覆盖，改动后建议设备上冒烟（创建→重启→确认恢复）。
