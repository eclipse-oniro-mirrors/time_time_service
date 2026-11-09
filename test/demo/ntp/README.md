# NTP 引擎真机验证方法

本文档给出两种真机验证方式：**A. 单元测试**（离线、确定性）与 **B. 独立 demo**（真实调引擎、走真实 NTP 服务器）。

> **产品/路径说明**：下文命令以 `rk3568` 产品、`out/rk3568/` 产物目录为例。真实环境的**产品名、产物目录、设备型号、镜像架构**可能不同——请将 `${product_name}`（产品名）、`out/${product_name}/`（产物目录）替换为实际值，并刷**与构建产物同架构**的镜像。

均需：

- 真机刷入**本源码树构建出的镜像**（架构须与构建产物一致，以 `out/${product_name}/args.gn` 的 `target_cpu` 为准；本示例为 32 位 arm）；
- `hdc` 已连接：`hdc list targets` 能看到设备。

---

## A. 单元测试 NtpTimeClientTest（推荐先跑这个）

覆盖 spec VM-1~VM-6、INV-5 及引擎/SA 各分支，网络层已 mock，**不依赖真实网络**，结果确定性。共 **21 个用例**。

```bash
# 1. 构建（如未构建）
hb build --product-name ${product_name} --build-target NtpTimeClientTest

# 2. 推送并执行（真机）
hdc file send out/${product_name}/tests/unittest/time_service/time_service/native/NtpTimeClientTest /data/local/tmp/
hdc shell "chmod +x /data/local/tmp/NtpTimeClientTest && /data/local/tmp/NtpTimeClientTest"
```

预期输出（gtest 汇总）：

```
[==========] 21 tests from 1 test suite ran.
[  PASSED  ] 21 tests.
```

若报缺库，补齐库路径：`hdc shell "LD_LIBRARY_PATH=/system/lib /data/local/tmp/NtpTimeClientTest"`。

---

## B. 独立 demo ntp_sync_demo（验证 innerkit 消费场景，eupdater 同款用法）

demo 链接 `libntp_time_client.z.so`，依次演示 6 个场景：
- 单服务器对时（`NtpTimeClient::RequestTime` 单参重载）；
- 多服务器连通性逐台检查；
- 策略一：第一个成功（`FIRST_SUCCESS`）；
- 策略二：选往返时延最小的服务器（`MIN_RTT`）；
- 策略三：多服务器多数表决（`VOTE`，≤100ms 聚簇投票）；
- 直接调用导出的 `SNTPClient` 符号。

```bash
# 1. 构建
hb build --product-name ${product_name} --build-target ntp_sync_demo

# 2. 推送 demo 与引擎 so 到真机（无需重刷镜像），并给 demo 加执行权限
hdc shell mkdir -p /data/local/tmp
hdc file send out/${product_name}/time/time_service/ntp_sync_demo /data/local/tmp/
hdc file send out/${product_name}/time/time_service/libntp_time_client.z.so /data/local/tmp/
hdc shell chmod +x /data/local/tmp/ntp_sync_demo

# 3. 运行（需真机可访问 UDP 123 外网）
hdc shell "cd /data/local/tmp && LD_LIBRARY_PATH=/data/local/tmp:/system/lib ./ntp_sync_demo 1.cn.pool.ntp.org time.windows.com"

# 可选：指定只跑某一种校准策略
hdc shell "cd /data/local/tmp && LD_LIBRARY_PATH=/data/local/tmp:/system/lib ./ntp_sync_demo --strategy=min_rtt 1.cn.pool.ntp.org time.windows.com"   # 只跑 MIN_RTT
hdc shell "cd /data/local/tmp && LD_LIBRARY_PATH=/data/local/tmp:/system/lib ./ntp_sync_demo --strategy=vote 1.cn.pool.ntp.org time.windows.com"      # 只跑 VOTE
hdc shell "cd /data/local/tmp && LD_LIBRARY_PATH=/data/local/tmp:/system/lib ./ntp_sync_demo --strategy=first_success 1.cn.pool.ntp.org"            # 只跑 FIRST_SUCCESS
```

参数：`--strategy=<first_success|min_rtt|vote>`（不传则跑全部三种）、`--timeout=<毫秒>`（单次请求超时，默认 5000）。

**两种运行模式**：
- **不传 `--strategy`**：完整演示 —— 单服务器对时 / 连通性 / 三种策略 / 直调 SNTPClient（`[1]~[6]`）；
- **指定 `--strategy`**：精简 —— 只跑连通性 + 该策略（`[1]~[2]`），跳过单服务器对时与直调。

服务器列表支持**空格**或**逗号**分隔（逗号格式与 SA 配置 `persist.time.ntpserver*` 一致）：
```bash
hdc shell "cd /data/local/tmp && LD_LIBRARY_PATH=/data/local/tmp:/system/lib ./ntp_sync_demo --strategy=vote ntp.ntsc.ac.cn,1.cn.pool.ntp.org,ntp.sjtu.edu.cn"
```

预期输出（示意，数值随网络/设备不同）：

```
========================================================
  NTP Time Sync Test (time_service sync engine)
========================================================

[Servers under test] 2
  - 1.cn.pool.ntp.org
  - time.windows.com

[1. Single-server sync] 1.cn.pool.ntp.org
  OK   errorCode=0
  Server          : 1.cn.pool.ntp.org
  NTP time        : 2026-11-03 15:06:19 (Beijing)  (ntpTimeMillis=1793689579455)
  Round-trip     : 405 ms (very slow)
  Clock offset   : 20760d 3h 35s BEHIND  (clockOffsetMs=1793674835203, relative to monotonic clock)
  Local clock    : 2026-11-03 15:06:19 (Beijing)  (device wall time)
  Clock deviation: <1s BEHIND standard time
  Verdict        : offset within 2s -> no calibration needed

[2. Server connectivity]
  OK   1.cn.pool.ntp.org      ntpTime=1793689579455 (2026-11-03 15:06:19 (Beijing))  rtt=405 ms (very slow)
  OK   time.windows.com       ntpTime=1793689580096 (2026-11-03 15:06:20 (Beijing))  rtt=63 ms (normal)

[3. Strategy: first success (FIRST_SUCCESS)]
  OK   errorCode=0  (selected: 1.cn.pool.ntp.org, rtt 405ms)

[4. Strategy: fastest reply (MIN_RTT)]
  OK   errorCode=0  (selected: time.windows.com, rtt 63ms)

[5. Strategy: majority vote (VOTE)]
  OK   errorCode=0  (selected: time.windows.com, rtt 63ms)

[6. Direct SNTPClient call]
  OK   ntpTime=1793689580096 (2026-11-03 15:06:20 (Beijing))  rtt=63 ms (normal)

========================================================
  Result: sync OK; local clock is <1s BEHIND standard time  (vs standard time)
========================================================
```

`OK` + `errorCode=0` 即该场景成功；`Clock offset` 是引擎返回的原始字段（**相对单调时钟的中间量，数值大小不代表墙钟偏差**）；`Clock deviation` 为负表示本机墙钟比标准时间快（基于设备墙钟与 NTP 时间之差，SA 免校即用此口径）；`Verdict` 依据 2s 阈值提示是否建议校时。`VOTE` 在多服务器时会按 ≤100ms 聚簇投票选择，若只剩一个可达服务器则直接采用它。

---

## C. 导出面与依赖审计（验证 VM-7 / INV-2，可选）

```bash
hdc shell "readelf -d /data/local/tmp/libntp_time_client.z.so | grep NEEDED"
# 预期仅系统基础库（libc / C++ 标准库 / securec / hilog）与编译器运行时 —— 无 samgr/ipc/common_event/safwk/hisysevent

hdc shell "nm -D /data/local/tmp/libntp_time_client.z.so | grep -E 'NtpTimeClient|SNTPClient'"
# 预期 12 个导出符号（2×RequestTime + 2×SNTPClient::RequestTime + 8 个 getter）
```

---

## 常见问题

- **`LD_LIBRARY_PATH` 找不到引擎 so**：确认推送了 `libntp_time_client.z.so`（SONAME 即 `libntp_time_client.z.so`，非 `libtime_ntp_client`）。
- **真机报 ABI 不匹配 / 无法加载**：镜像与二进制架构不一致（示例为 32 位 arm，64 位产品需对应镜像）。
- **demo 对时全失败（77856781）**：真机无外网 UDP 123，或 NTP 服务器不可达；换可达服务器重试。
- **gn gen 偶发 "Not allow import other gni"**：环境既有问题（`out/${product_name}/gn_log.json` 被失败运行写坏）。**修复：删除 `out/${product_name}/gn_log.json` 后重跑**（已验证恢复 gn gen）。
