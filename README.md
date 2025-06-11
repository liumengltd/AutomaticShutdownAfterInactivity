# Windows 10/11无操作自动关机助手

一个简单的Windows无操作自动关机助手，可以在指定时间后无操作一定时间自动关机，同时支持创建Windows计划任务，开机自启动。

## 功能特点

- 检测用户键盘和鼠标活动
- 一定时间内无操作自动关机
- 支持设置空闲时间阈值
- 支持创建Windows计划任务，开机自启动

## 使用方法

### 基本用法

直接运行程序，默认设置为闲置30分钟无活动将自动关机：

```
LiuMengAutomaticShutdownAfterInactivity.exe
```

### 命令行参数

- `-time`: 设置空闲时间阈值（分钟），默认为30分钟
- `-hour`: 设置开始监控的小时（24小时制）
- `-minute`: 设置开始监控的分钟
- `-interval`: 设置检查系统活动的间隔（秒）,默认为10
- `-task`: 创建Windows计划任务，系统启动时自动运行

### 示例

设置空闲时间为5分钟：

```
LiuMengAutomaticShutdownAfterInactivity.exe -time 5
```

设置开始侦听时间为22:00

```
LiuMengAutomaticShutdownAfterInactivity.exe -hour 22 -minute 0
```

设置检查系统活动的间隔为5秒，并创建计划任务：

```
LiuMengAutomaticShutdownAfterInactivity.exe -interval 5 -task
```

设置空闲时间为5分钟，开始侦听时间为22:00，检查系统活动的间隔为5秒

```
LiuMengAutomaticShutdownAfterInactivity.exe -time 5 -hour 22 -minute 0 -interval 5
```

创建Windows计划任务：

```
LiuMengAutomaticShutdownAfterInactivity.exe -task
```

同时设置空闲时间、起始时间和检查间隔并创建任务：

```
LiuMengAutomaticShutdownAfterInactivity.exe -time 5 -hour 22 -minute 0 -interval 5 -task
```

## 工作原理

1. 程序启动后，会监控用户输入和时间
2. 如果在设定的时间内没有检测到用户活动（键盘或鼠标），则执行关机命令
3. 如果在此期间检测到用户活动，则取消关机计划

## 系统要求

- Windows操作系统
- 管理员权限（创建计划任务时需要）

## 授权协议

本仓库采用的是Apache License 2.0协议，详情请看[LICENSE](LICENSE)文件。