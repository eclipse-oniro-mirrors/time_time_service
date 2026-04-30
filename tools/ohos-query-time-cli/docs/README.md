# ohos-queryTime 使用文档

## 简介

`ohos-queryTime` 是 OpenHarmony 系统的时间查询 CLI 工具，提供系统时间相关信息的查询功能。

## 功能特性

- 获取 UTC 时间（从 1970-01-01 00:00:00 UTC 开始的毫秒数）
- 获取系统开机时间（包含休眠时间，单位：毫秒）
- 获取单调时间（不包含休眠时间，单位：毫秒）
- 获取当前时区 ID

## 命令说明

### get-wall-time

获取 UTC 时间（Wall Time）。

```bash
ohos-queryTime get-wall-time
```

**输出示例**:
```
1714305600000
```

**说明**: 返回从 1970-01-01 00:00:00 UTC 开始的毫秒数。

---

### get-boot-time

获取系统开机时间（包含休眠时间）。

```bash
ohos-queryTime get-boot-time
```

**输出示例**:
```
3600000
```

**说明**: 返回系统开机以来的毫秒数，包含系统休眠的时间。

---

### get-monotonic-time

获取单调时间（不包含休眠时间）。

```bash
ohos-queryTime get-monotonic-time
```

**输出示例**:
```
3500000
```

**说明**: 返回系统开机以来的毫秒数，不包含系统休眠的时间。适用于需要精确计时的场景。

---

### get-time-zone

获取当前时区 ID。

```bash
ohos-queryTime get-time-zone
```

**输出示例**:
```
Asia/Shanghai
```

**说明**: 返回当前系统的时区 ID，如 "Asia/Shanghai"、"America/New_York" 等。

---

### --help

显示帮助信息。

```bash
ohos-queryTime --help
```

---

### --version

显示版本信息。

```bash
ohos-queryTime --version
```

**输出示例**:
```
ohos-queryTime version 1.0.0
```

## 使用示例

### 示例 1: 获取当前 UTC 时间

```bash
$ ohos-queryTime get-wall-time
1714305600000
```

### 示例 2: 获取系统开机时间

```bash
$ ohos-queryTime get-boot-time
3600000
```

### 示例 3: 获取单调时间（用于计时）

```bash
$ ohos-queryTime get-monotonic-time
3500000
```

### 示例 4: 获取当前时区

```bash
$ ohos-queryTime get-time-zone
Asia/Shanghai
```

### 示例 5: 显示帮助信息

```bash
$ ohos-queryTime --help
ohos-queryTime - Query system time information

Usage: ohos-queryTime <command>

Commands:
  get-wall-time          Get wall time (UTC time in milliseconds)
  get-boot-time          Get boot time (including sleep time)
  get-monotonic-time     Get monotonic time (excluding sleep time)
  get-time-zone          Get current time zone

Options:
  --help                 Show this help message
  --version              Show version information
```

## 注意事项

1. **权限要求**: 本工具为纯查询工具，无需任何特殊权限。

2. **时间精度**: 所有时间值均以毫秒为单位返回。

3. **时区格式**: 时区 ID 遵循 IANA 时区数据库格式（如 "Asia/Shanghai"）。

4. **单调时间**: 单调时间（monotonic time）在系统休眠时会暂停，适用于需要精确计时的场景。

5. **开机时间**: 开机时间（boot time）包含系统休眠的时间，反映实际的物理时间流逝。

## 故障排除

### 问题 1: 命令返回错误码

**现象**:
```
Error: Failed to get wall time, ret=-1
```

**解决方法**:
- 确保系统服务正常运行
- 检查系统日志获取详细信息

### 问题 2: 无法连接到 TimeService

**现象**:
```
Error: Failed to get TimeServiceClient instance
```

**解决方法**:
- 确保 `time_service` 系统能力已启动
- 检查系统服务状态

## 相关资源

- [OpenHarmony 时间服务文档](https://gitee.com/openharmony/docs)
- [IANA 时区数据库](https://www.iana.org/time-zones)

## 版本历史

### v1.0.0 (2025-04-28)

- 初始版本
- 支持 4 个查询命令：get-wall-time、get-boot-time、get-monotonic-time、get-time-zone
- 支持 --help 和 --version 选项
