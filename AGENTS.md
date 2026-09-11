# AGENTS.md

## 1. 代码地图

本 AGENTS.md 适用于仓库根目录。子目录可能包含更具体的规则文件。

嵌套指令文件：
- `docs/agent/feature-time.md` — 时间与时区（SetTime / RTC / 时区 / NTP / tick / 广播）
- `docs/agent/feature-timer.md` — 定时器（调度线程 / 持久化 / 代理 / 电源）
- `docs/agent/feature-js-api.md` — 多语言 API 框架（NAPI / ANI / Taihe / C API / 仓颉 / inner_api）

本仓库实现 OpenHarmony **时间子系统核心部件**（子系统 `time`，部件 `time_service`，SA ID `3702`，syscap `SystemCapability.MiscServices.Time`），职责是系统时间设置/查询、时区管理、NTP 时间同步、定时器服务。

最重要的架构边界是**语言面与业务实现分离**：`framework/`（NAPI/ANI/Taihe/仓颉）与 `interfaces/`（inner_api 客户端、C API）只做绑定与代理，业务实现全部在 SA（`services/`）。两层之间的契约是 IDL：服务侧 `services/ITimeService.idl` / `ITimerCallback.idl`，ArkTS 侧 `framework/js/taihe/*/idl/*.taihe`。

**三层结构**：

| 层 | 路径 | 用途 |
|---|---|---|
| 语言面 | `framework/js/napi/`（systemDateTime / systemTime / systemTimer）、`framework/js/ani/`、`framework/js/taihe/`、`framework/cj/`、`interfaces/kits/c/` | JS/ArkTS/C/仓颉绑定 |
| 客户端 | `interfaces/inner_api/`（`TimeServiceClient` 单例、`ITimerInfo` 回调） | 各语言面与系统模块共用的服务代理 |
| 服务端 | `services/`（`TimeSystemAbility` 主 SA + `time/` + `timer/` + `dfx/`） | 全部业务实现 |

关键路径：

| 路径 | 职责 | 变更风险 |
|---|---|---|
| `services/time_system_ability.cpp/.h` | SA 主实现：IPC 入口、权限校验、RTC、重启恢复 | 全部接口的入口，权限模型集中于此 |
| `services/ITimeService.idl` | IPC 接口定义（生成 proxy/stub） | 接口码二进制兼容，顺序不可改 |
| `services/time/` | 时间/时区/NTP/tick/广播发布订阅 | 时间同步与广播契约 |
| `services/timer/` | 定时器子系统（调度线程、持久化、代理、电源） | 锁与线程模型复杂，核心风险区 |
| `services/dfx/` | hisysevent 打点、hidumper 命令 | 事件契约 |
| `framework/js/taihe/` | 新一代 ArkTS 接口（IDL 生成 + 手写 impl） | 生成物不可手改 |
| `interfaces/inner_api/` | 客户端单例、SA 重启自愈、定时器回调链 | 下游依赖（platformsdk/sasdk） |
| `services/etc/` | `time.para`（系统参数默认值）、init 配置、SA profile | 持久化契约与 DAC |
| `time.gni` / `bundle.json` | 编译开关与部件配置 | 影响整机构建 |
| `hisysevent.yaml` | HiSysEvent 事件定义 | 打点契约 |
| `utils/native/` | hilog 封装、xcollie、文件工具 | 全模块引用 |

Where to look：

- 时间/时区/NTP/广播行为变更 → `services/time/` + `docs/agent/feature-time.md`
- 定时器行为变更 → `services/timer/` + `docs/agent/feature-timer.md`
- JS/ArkTS/C/仓颉接口或客户端变更 → `framework/` / `interfaces/` + `docs/agent/feature-js-api.md`
- 权限/IPC 接口变更 → `services/time_system_ability.cpp` + `services/time_permission.cpp`
- 打点/hidumper 变更 → `services/dfx/` + `hisysevent.yaml`
- 编译开关 → `time.gni` + `bundle.json` features
- 测试变更 → 先看 `test/unittest/` 同目录既有用例的模式与覆盖

## 2. 知识路由

以下文档不是可选背景阅读。当任务命中对应类别时，必须在规划前阅读匹配文档。

### Task-based routing

- 时间设置、时区、NTP 同步、tick、时间类广播变更 → 阅读 `docs/agent/feature-time.md`
- 定时器创建/启动/调度/持久化/代理/关机闹钟/运行锁变更 → 阅读 `docs/agent/feature-timer.md`
- NAPI/ANI/Taihe/C API/仓颉接口、inner_api 客户端、回调链变更 → 阅读 `docs/agent/feature-js-api.md`
- 权限模型变更 → 阅读 `docs/agent/feature-time.md` §2.1 + 本文件 §3

### Path-based routing

- `services/time/`、`services/time_system_ability.cpp`（时间部分）→ `docs/agent/feature-time.md`
- `services/timer/` → `docs/agent/feature-timer.md`
- `framework/`、`interfaces/` → `docs/agent/feature-js-api.md`
- `services/dfx/`、`hisysevent.yaml` → 本文件 §4 + 相关 feature 文档的验证节

### Vocabulary-based routing

当任务、issue、日志、API 名称或变更文件中出现以下术语时，在规划前阅读链接文档：

| 术语 | 风险提示 | 阅读 |
|---|---|---|
| TimerLooper | 定时器调度专线程，唯一操作 `alarmBatches_` 与内核 timerfd；投递必须持锁外执行否则死锁 | feature-timer §2 |
| timerEntryMap_ / alarmBatches_ | 两套数据两把锁，锁顺序 `entryMapMutex_` → `mutex_` 不可反序 | feature-timer §2 |
| hold_on_reboot / drop_on_reboot | 持久化双表：重启后恢复 / 重启后丢弃；表结构变更须同步 COLUMN_INDEX_* 三处 | feature-timer §4 |
| E_SQLITE_CORRUPT / RecoverDataBase | 数据库损坏自愈路径，依赖 StoreGuard 引用计数等待 in-flight 操作 | feature-timer §4 |
| ECANCELED / ALARM_TIME_CHANGE_MASK | CLOCK_REALTIME fd 收到即"系统时间被修改"，触发全量重排 | feature-timer §2 |
| ProxyTimer | 系统级定时器代理（延迟 3 天），仅 native/shell 可调 | feature-timer §5 |
| CLOCK_POWEROFF_ALARM | 关机闹钟；`itimerspec` 必须值初始化防重复关机 | feature-timer §6 |
| NtpTrustedTime | NTP 结果信任判定（一天 RTC 漂移 2000ms 容忍 + 多服务器投票） | feature-time §2.4 |
| TimeTickNotify | 每分钟整分 tick；`timerId_` 必须 atomic（加锁会死锁） | feature-time §2.5 |
| common.event.TIMER_TRIGGER | 定向发布给 RSS（UID 1096），不得改为公开广播 | feature-time §2.6 |
| checkedBundles_ | CheckAuthorization 仅对 settings 白名单生效的特权校验 | feature-time §2.1 |
| persist.time.* | 系统参数即持久化契约（timezone/ntpserver/auto_time 等），改名破坏兼容 | feature-time §2 |
| Taihe / .taihe | IDL 生成层；生成的 `.ani.cpp`/`.impl.hpp` 等不可手改，`.impl.cpp` 手写 | feature-js-api §3 |
| TIME_GETTIME_RANDOM / GetMonotoneWallTimeNs | 防时间回退攻击的单调墙钟，三层共享，勿单层移除 | feature-js-api §6 |
| recoverTimerInfoMap_ | SA 重启后客户端自动恢复定时器的登记表 | feature-js-api §4 |
| ITimerCallback / OnTrigger | 定时器到期回调链（SA → 客户端 stub → 各语言面） | feature-js-api §4 |
| ALARM_COUNT / BEHAVIOR_TIMER | HiSysEvent 打点契约（domain TIME） | feature-timer §7 |

在计划中声明：
- 任务类别
- 已读文档
- 发现的约束
- 是否应使用特定 Skill/工作流

## 3. 约束边界

### 架构不变量

- 语言面（framework/interfaces）不实现业务，业务全部在 SA（services/）；新增能力先改服务实现，再铺语言面。
- IPC 接口码由 `services/ITimeService.idl` 声明顺序决定（从 `MIN_TRANSACTION_ID` 连续递增），新方法只能追加在末尾，不得插入或重排。
- IDL/Taihe 生成的代码是编译期产物，不得手改；改 `.idl` / `.taihe` 后依赖构建重新生成。
- `TimerLooper` 是唯一操作 `alarmBatches_` 与内核 timerfd 的线程；投递（WantAgent/RunningLock/回调）在 `mutex_` 锁外执行。
- 系统参数 `persist.time.*` 是跨重启持久化契约，参数名与默认值变更影响兼容性与 DAC。
- ANI 层（`framework/js/ani/`）刻意只绑定 `getTime`/`getTimezoneSync` 两个高频只读 API，不做全量覆盖。
- 新增代码注释一律用英文（本项目约定）。

### Do not

- 不要变更 IDL 方法顺序、签名或 `[oneway]` 标注（除非任务明确要求并评估二进制兼容）。
- 不要在持有 `mutex_`/`entryMapMutex_` 时执行投递、WantAgent 通知或 PowerManager 交互。
- 不要手改任何生成文件（Taihe 的 `.ani.cpp`/`.abi.c`/`.proj.hpp`/`.impl.hpp`，IDL 生成的 proxy/stub）。
- 不要删除或脱敏 `SetRealTime` 的 WARN 级时间篡改审计日志。
- 不要绕过或简化 SetTime 三段权限校验（系统应用 → SET_TIME 权限 → CheckAuthorization 白名单）。
- 不要把 `common.event.TIMER_TRIGGER` 改为公开广播。
- 不要向已停止维护的 `@ohos.systemTime`（NAPI 旧模块）新增 API。
- 不要在 NAPI `execute`（子线程）中调用 napi JS 交互 API。
- 不要改表列顺序而不同步 `timer_database.h` 的 `COLUMN_INDEX_*` 与 `time_system_ability.cpp`、`timer_manager.cpp` 两处 `ALL_DATA`。
- 不要为通过测试删除日志、HiSysEvent 打点或错误码。
- 不要在没有显式批准的情况下引入新的生产依赖或变更 license 敏感代码。

### Ask before

- 新增或变更公共 API（IDL、Taihe、NAPI、C API、仓颉）。
- 变更权限模型（含 `checkedBundles_` 白名单、系统参数 DAC）。
- 变更加密、NTP 信任判定等安全相关策略。
- 变更定时器持久化表结构或数据库版本。
- 变更 `time.gni` / `bundle.json` 编译开关默认值。
- 删除兼容性适配或数据迁移逻辑（CJSON→RDB 迁移、数据库升级）。

## 4. 验证

### 最小验证

前提：`openharmony/` 根目录下已执行 `source build/envsetup.sh`。

- 编译源码：`./build.sh --product-name rk3568 --build-target time_service`（等价 `hb build --product-name=rk3568 --build-target time_service`）
- 编译测试：`./build.sh --product-name rk3568 --build-target time_service_test`
- 单测试 target：`./build.sh --product-name rk3568 --build-target TimeServiceTimerTest`（target 名见 feature-js-api §8）
- 精确模块 target：`./build.sh --product-name rk3568 --build-target base/time/time_service/services:time_system_ability --ccache`
- **fast-rebuild 会触发 prebuilts 联网下载 nodejs 校验，网络不通时用普通编译命令**
- C++ 格式化：对照 `.clang-format`（`git-clang-format`）
- API 兼容性：检查公共接口签名、错误码、权限行为是否保持兼容

### 任务级验证

- 时间/时区/NTP 变更 → `TimeServiceTimeTest` + 设备 `hdc shell hidumper -s 3702 -a "-time"`
- 定时器变更 → `TimeServiceTimerTest`；持久化相关加 `TimerDatabaseTest`，并考虑 `time_service_rdb_enable=false` 的 CJSON 降级编译
- 代理/调整/锁优化 → `TimeProxyTest` / `TimerLockOptimizerTest`
- 语言面/客户端变更 → `TimeClientTest` + `TimeServiceBasicTest`；JS 接口跑 js_test HAP
- 权限变更 → `TimePermissionTest` + 无权限 js_test 组
- 打点/DFX 变更 → `TimeDfxTest`；对照 `hisysevent.yaml` 检查事件定义一致性
- 仅测试变更 → 运行变更的测试及至少一个相邻相关测试

### Done 定义

任务完成仅在以下条件全部满足时：
- 请求的行为已实现。
- 相关构建/测试/lint/兼容性检查已执行，或已说明无法执行的原因。
- 最终回复包含：变更摘要、变更文件列表、验证结果、剩余风险。
- 不包含无关的格式化、重构或附带变更。
- 测试覆盖：修改和新代码有 UT 覆盖；新增外部接口有 FUZZ 测试覆盖。

### 测试约束

- 单测框架 gtest（`HWTEST_F`），用例命名：`被测方法_测试场景_预期结果`。
- 测试用例必须包含显式断言（EXPECT/ASSERT），禁止无断言或不可能失败的断言。
- service_test 沿用既有 mock 模式，勿引入 gmock：`#define private public` 宏 + 静态链接 `time_system_ability_static` + `nativetoken_kit` 注入权限 token + `TimePermission::SetAuthorizationClient` 注入 mock。
- 条件编译的代码（见 feature-timer §6 宏表）至少验证默认开关组合可编译。

## 5. 其他参考文档

以下为仓库内过程性/分析性文档（非路由目标，按需查阅）：
- `docs/存储问题DFX设计.md` — 定时器数据库自愈 + 巡检 + 打点设计
- `docs/覆盖率分析与补充计划.md` — 单测覆盖缺口清单
- `docs/superpowers/` — 历史设计稿与实现计划
