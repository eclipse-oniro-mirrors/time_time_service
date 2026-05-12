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

**成功输出示例**:
```json
{"type":"result","status":"success","data":{"time":1714305600000,"unit":"ms"}}
```

**失败输出示例**:
```json
{"type":"result","status":"failed","errCode":"ERR_GET_WALL_TIME","errMsg":"Failed to get wall time","suggestion":"Check system time service status and permissions"}
```

**说明**: 返回从 1970-01-01 00:00:00 UTC 开始的毫秒数。

---

### get-boot-time

获取系统开机时间（包含休眠时间）。

```bash
ohos-queryTime get-boot-time
```

**成功输出示例**:
```json
{"type":"result","status":"success","data":{"time":3600000,"unit":"ms"}}
```

**失败输出示例**:
```json
{"type":"result","status":"failed","errCode":"ERR_GET_BOOT_TIME","errMsg":"Failed to get boot time","suggestion":"Check system time service status"}
```

**说明**: 返回系统开机以来的毫秒数，包含系统休眠的时间。

---

### get-monotonic-time

获取单调时间（不包含休眠时间）。

```bash
ohos-queryTime get-monotonic-time
```

**成功输出示例**:
```json
{"type":"result","status":"success","data":{"time":3500000,"unit":"ms"}}
```

**失败输出示例**:
```json
{"type":"result","status":"failed","errCode":"ERR_GET_MONOTONIC_TIME","errMsg":"Failed to get monotonic time","suggestion":"Check system time service status"}
```

**说明**: 返回系统开机以来的毫秒数，不包含系统休眠的时间。适用于需要精确计时的场景。

---

### get-time-zone

获取当前时区 ID。

```bash
ohos-queryTime get-time-zone
```

**成功输出示例**:
```json
{"type":"result","status":"success","data":{"timezone":"Asia/Shanghai"}}
```

**失败输出示例**:
```json
{"type":"result","status":"failed","errCode":"ERR_GET_TIME_ZONE","errMsg":"Failed to get time zone","suggestion":"Check system time service status"}
```

**说明**: 返回当前系统的时区 ID，如 "Asia/Shanghai"、"America/New_York" 等。

---

### --help

显示帮助信息。

```bash
ohos-queryTime --help
```

**输出示例**:
```
ohos-queryTime - Query system time information

Usage:
  ohos-queryTime <command> [options]

Parameters:
  --help             Display this help message

SubCommands:
  get-wall-time      Get wall time (UTC time in milliseconds)
  get-boot-time      Get boot time (including sleep time)
  get-monotonic-time Get monotonic time (excluding sleep time)
  get-time-zone      Get current time zone

Examples:
  ohos-queryTime --help
  ohos-queryTime get-wall-time
  ohos-queryTime get-wall-time --help
```

---

## 通用错误码

| 错误码 | 说明 | 常见原因 |
|--------|------|----------|
| `E_NO_COMMAND` | 未指定命令 | 调用时缺少子命令参数 |
| `E_UNKNOWN_COMMAND` | 未知命令 | 使用了不存在的子命令 |
| `ERR_CLIENT_INIT` | 客户端初始化失败 | time_service 系统能力未启动 |
| `ERR_GET_WALL_TIME` | 获取 UTC 时间失败 | 系统时间服务异常 |
| `ERR_GET_BOOT_TIME` | 获取开机时间失败 | 系统时间服务异常 |
| `ERR_GET_MONOTONIC_TIME` | 获取单调时间失败 | 系统时间服务异常 |
| `ERR_GET_TIME_ZONE` | 获取时区失败 | 系统时间服务异常 |

## 注意事项

1. **权限要求**: 本工具为纯查询工具，无需任何特殊权限。

2. **时间精度**: 所有时间值均以毫秒为单位返回。

3. **时区格式**: 时区 ID 遵循 IANA 时区数据库格式（如 "Asia/Shanghai"）。

4. **单调时间**: 单调时间（monotonic time）在系统休眠时会暂停，适用于需要精确计时的场景。

5. **开机时间**: 开机时间（boot time）包含系统休眠的时间，反映实际的物理时间流逝。

6. **JSON 输出格式**: 所有命令返回统一的 JSON 格式，包含 `type`、`status`、`data`（成功时）或 `errCode`、`errMsg`、`suggestion`（失败时）字段。

## 故障排除

### 问题 1: 命令返回错误码

**现象**:
```json
{"type":"result","status":"failed","errCode":"ERR_GET_WALL_TIME","errMsg":"Failed to get wall time","suggestion":"Check system time service status and permissions"}
```

**解决方法**:
- 确保系统服务正常运行
- 检查系统日志获取详细信息
- 确认 time_service 系统能力已启动

### 问题 2: 无法连接到 TimeService

**现象**:
```json
{"type":"result","status":"failed","errCode":"ERR_CLIENT_INIT","errMsg":"Failed to initialize TimeServiceClient","suggestion":"Check if time_service system ability is running"}
```

**解决方法**:
- 确保 `time_service` 系统能力已启动
- 检查系统服务状态
- 重启 time_service 服务

## 相关资源

- [OpenHarmony 时间服务文档](https://gitee.com/openharmony/docs)
- [IANA 时区数据库](https://www.iana.org/time-zones)
