# feature-time.md — 时间与时区领域知识

> 本文档为 Agent 知识路由目标，由根 AGENTS.md 的 task-based / path-based / vocabulary-based routing 触发阅读。
> Agent 能自己探索出来的少写；Agent 猜不准、猜错代价高、团队必须统一执行的内容要写。

## 1. Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 时间设置（SetTime/SetAutoTime） | `services/time_system_ability.cpp`（`SetTime`/`SetRealTime`/`SetRtcTime`） |
| RTC 硬件时钟写入 | `services/time_system_ability.cpp`（`GetWallClockRtcId`/`CheckRtc`/`WriteRtcTime`） |
| 时区设置与解析 | `services/time/src/time_zone_info.cpp`（`SetTimezone`/`SetTimezoneToKernel`） |
| NTP 同步 | `services/time/src/ntp_update_time.cpp` + `services/time/src/ntp_trusted_time.cpp` + `services/time/src/sntp_client.cpp` |
| 时间/时区/tick 广播发布 | `services/time/src/time_service_notify.cpp` |
| 每分钟 tick | `services/time/src/time_tick_notify.cpp` |
| 广播订阅（网络/亮灭屏/NITZ/卸载） | `services/time/src/event_manager.cpp` |
| 权限校验 | `services/time_permission.cpp` |
| 行为打点 | `services/dfx/src/time_sysevent.cpp` |
| 系统参数默认值 | `services/etc/time.para`（DAC 见 `services/etc/time.para.dac`） |

## 2. 核心链路

### 2.1 SetTime（IPC 入口权限三段校验）

`SetTime`（`time_system_ability.cpp`）的校验顺序，改任何一段都会破坏权限模型：

1. `apiVersion == API_VERSION_9` 时 `CheckSystemUidCallingPermission`（仅 API9 限制系统应用，旧版本跳过）
2. `CheckCallingPermission(SET_TIME)` —— `AccessTokenKit::VerifyAccessToken` 校验 `ohos.permission.SET_TIME`
3. `CheckAuthorization(ohos.privilege.modify_system_time)` —— **仅对 `checkedBundles_ = {"settings"}` 白名单生效**（`time_permission.cpp`），防止非管理员用户经设置应用改时间；白名单外的系统应用直接放行

通过后走 `SetTimeInner` → `SetRealTime`：
1. `settimeofday` 写内核 wall clock
2. `SetRtcTime`：`ioctl(RTC_SET_TIME)` 写硬件 RTC。RTC 设备号由 `GetWallClockRtcId` 扫描 `/sys/class/rtc/rtc*/hctosys` 确定（选带 hctosys 标志的那个）
3. 时间变化 >1ms 时 `PublishTimeChangeEvents` 发布 `usual.event.TIME_CHANGED`
4. 立即触发 `TimeTickNotify::Callback()`（保证改时间后 tick 序列快速恢复）
5. `TimeBehaviorReport` 上报 HiSysEvent

`SetTimeInner` 是**服务内部免检入口**：NTP 同步、NITZ 等服务内部来源改时间走它，绕过 IPC 层权限校验。

### 2.2 SetAutoTime

`SetAutoTime` 只写系统参数 `persist.time.auto_time`（"ON"/"OFF"），不直接改时间。`NtpUpdateTime` 监听该参数变化（`AUTO_TIME_CHANGE`）决定是否启动/停止 NTP 同步。权限链路与 SetTime 相同（系统应用 + SET_TIME + CheckAuthorization）。

### 2.3 时区设置

`SetTimeZone` → `SetTimeZoneInner` → `TimeZoneInfo::SetTimezone`（`time_zone_info.cpp`）：
1. 与当前时区相同则跳过
2. 校验时区 ID 在可用列表中；不在则查转换表 `ConvertTimeZone` 映射到标准名
3. `setenv("TZ", ...)` + `tzset()` 更新本进程时区环境
4. `SetTimezoneToKernel`：`settimeofday(nullptr, &tz)`，其中 `tz_minuteswest = -tm_gmtoff / 60`（注意符号取反）
5. `SetParameter("persist.time.timezone", ...)` 持久化（默认值 `Asia/Shanghai`，见 `time.para`）
6. 发布 `usual.event.TIMEZONE_CHANGED`

时区数据文件（设备侧，非本仓库）：
- 可用时区列表：优先 `/system/etc/tzdata_distro/timezone_list.cfg`，不存在则 `/system/etc/zoneinfo/timezone_list.cfg`
- 非标准名转换表：`/system/etc/zoneinfo/timezone_convert.txt`（每行 `key:value`）

### 2.4 NTP 同步链路

`NtpUpdateTime`（编排/重试）→ `NtpTrustedTime`(结果信任判定) → `SNTPClient`（协议交互）。

**服务器来源**（逗号分隔，最多 5 个，`NTP_MAX_SIZE`）：
- `persist.time.ntpserver`（默认 `1.cn.pool.ntp.org`）
- `persist.time.ntpserver_specific`（特定服务器，优先于普通服务器）

**触发时机**（`NtpUpdateSource`，六种）：INIT / REGISTER_SUBSCRIBER（广播注册成功后）/ NET_CONNECTED（网络连通，`COMMON_EVENT_CONNECTIVITY_CHANGE` code==3）/ NTP_SERVER_CHANGE（`SystemWatchParameter` 监听服务器参数）/ AUTO_TIME_CHANGE（监听自动同步开关）/ RETRY_BY_TIMER（定时器重试）。

**重试退避**：失败后从 10s（`MIN_NTP_RETRY_INTERVAL`）开始每次 ×4，上限 12h（`MAX_NTP_RETRY_INTERVAL`）；成功或开关关闭重置为 12h。

**结果信任判定**（`NtpTrustedTime`）：
- `ForceRefreshTrusted`：直接信任并替换（用于特定服务器）
- `ForceRefresh`：要求与已有可信时间差不超过一天（RTC 漂移容忍 2000ms），否则拒收
- 所有服务器都不可信时 `FindBestTimeResult` 对候选列表**投票**，取超过半数一致的结果
- `FindBestTimeResult` 中耗时操作（`GetBootTimeMs`/`TimeBehaviorReport`）刻意移到锁外，避免阻塞高频的 `CurrentTimeMillis` 查询导致 watchdog

**SNTP 协议细节**（`sntp_client.cpp`）：
- UDP socket 连服务器 123 端口，5s 超时，48 字节 NTP 报文，计算 clock offset 与 round trip delay
- `CreateConnectedSocket` 固定 `AF_INET`——**不支持 IPv6 NTP 服务器**
- `ConvertNtpToStamp` 校验 `second < SECONDS_SINCE_FIRST_EPOCH` 返回 0，防异常时间戳

### 2.5 每分钟 tick

`TimeTickNotify`（`time_tick_notify.cpp`）内部用一个 RTC（非唤醒）定时器实现：
- `Init`：计算下一个整分钟触发时间，启动内部定时器
- `Callback`：仅在触发落在整分钟后第一秒内（`timeMilliseconds < 1000`）且距上次发布 >1s 时发布 `usual.event.TIME_TICK`（去重），随后重排到下一个整分钟
- 亮灭屏广播（`COMMON_EVENT_SCREEN_ON`）也会触发 `Callback`，保证休眠错过 tick 后快速恢复

**线程/锁坑**：`timerId_` 用 `std::atomic` 而非加锁——`GetTickTimerId()` 会被 `TimerManager::StartTimer` 在持有 `entryMapMutex_` 时调用，而 `Callback` 持有 `timeridMutex_` 后也调 `StartTimer`；若 `GetTickTimerId` 加同一把锁会死锁（见 `time_tick_notify.h` 注释）。

### 2.6 CommonEvent 事件清单

发布（`time_service_notify.cpp`）：

| 事件 | 发布时机 | 备注 |
|---|---|---|
| `usual.event.TIME_CHANGED` | SetTime 时间变化 >1ms | |
| `usual.event.TIMEZONE_CHANGED` | 时区变化 | |
| `usual.event.TIME_TICK` | 每分钟整分 | 非唤醒，深度睡眠期间不发布 |
| `common.event.TIMER_TRIGGER` | 定时器触发 | **定向发布**：`SetSubscriberUid({UID_RSS=1096})`，仅资源调度服务订阅，勿改为公开广播 |

订阅（`event_manager.cpp`，注册失败重试最多 6 次）：

| 事件 | 处理 |
|---|---|
| `COMMON_EVENT_CONNECTIVITY_CHANGE`(code==3) | 触发 NTP 同步（`IsInUpdateInterval` 决定是否新开 detached 线程） |
| `COMMON_EVENT_SCREEN_ON` | 触发 tick callback |
| `COMMON_EVENT_NITZ_TIME_CHANGED` | `UpdateNITZSetTime` 更新 NITZ 时间 |
| `COMMON_EVENT_PACKAGE_REMOVED`/`BUNDLE_REMOVED`/`PACKAGE_FULLY_REMOVED` | `TimerManager::OnPackageRemoved(uid)` 清理被卸载应用定时器 |

**坑**：广播注册失败若不重试成功，被卸载应用的定时器不会被清理，会在数据库中持续累积（`time_system_ability.cpp` `RegisterSubscriber` 注释）。

## 3. 硬约束

### 禁止事项

- NEVER 变更 `services/ITimeService.idl` 中方法的顺序或在中间插入方法——生成的 IPC 接口码从 `MIN_TRANSACTION_ID` 连续递增，改顺序破坏与所有已编译客户端 Proxy 的二进制兼容（新方法只能追加在末尾）。
- NEVER 删除或脱敏 `SetRealTime` 的 WARN 级审计日志（明文 uid/pid/beforeTime/setTime/difference）——这是时间篡改的可追溯性要求，代码注释中明确说明。
- NEVER 移除 `SetTimezoneToKernel` 中 `tm_gmtoff` 的 ±86400s 范围校验（防 `settimeofday` 写入异常值与 `-LONG_MIN` UB）。
- NEVER 把 `common.event.TIMER_TRIGGER` 改为公开广播（当前仅 RSS 订阅，公开会导致事件风暴）。
- NEVER 在 NTP 校验逻辑中放宽"一天 RTC 漂移 2000ms"的信任阈值，除非任务明确要求（放宽等于接受任意 NTP 伪造时间）。

### 必须先问人

- 变更 IDL 接口（新增/改名/改参数/改顺序）。
- 变更权限模型（含 `checkedBundles_` 白名单内容）。
- 变更 `persist.time.*` 系统参数名或默认值（涉及兼容性与 DAC 配置）。
- 变更 NTP 信任判定策略。

### 易错点

- 时区列表/转换表解析遇空行 `break` 而非 `continue`——文件中间的空行会使后续条目全部失效；修改解析逻辑或数据文件时注意保持无空行。
- `SNTPClient` 仅 IPv4；如果任务要求支持 IPv6 NTP，需重写 `CreateConnectedSocket`。
- `SetAutoTime` 与 NTP 是"开关 + 执行"关系：改开关逻辑时必须同步考虑 `NtpUpdateTime` 的参数监听。

## 4. 验证

> 通用构建/lint/Done 定义见根 AGENTS.md §4。

- 时间/时区行为变更：跑 `TimeServiceTimeTest`（`test/unittest/service_test/src/time_service_time_test.cpp`，NTP 用例也在其中）。
- 系统参数变更：检查 `services/etc/time.para` 与 `time.para.dac` 权限一致性（`persist.time.auto_time` 为 0777 全开放，其余 0775）。
- 广播变更：设备上 `hdc shell hidumper -s 3702 -a "-time"` 验证服务状态输出。
