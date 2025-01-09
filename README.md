# Network Trigger / 网络触发器

这是一个用于监控网络请求并获取发起进程信息的Python工具。可以实时监控特定目标的TCP/UDP请求，并显示发起请求的进程信息。

## 主要功能
- 监控指定目标的网络请求
- 获取发起请求的进程信息（PID、进程名、命令行参数、用户等）
- 支持TCP和UDP协议
- 详细的日志记录（控制台和文件）
- 自动解析域名到IP地址
- 支持多目标监控

## 依赖要求
- Python 3.x
- 依赖包：
  - scapy
  - psutil
  - argparse
  - logging

## 使用方法
```bash
python trigger.py -t <目标地址> [-i <网络接口>]
```

### 参数说明
- `-t/--target`: 要监控的目标地址（IP或域名），可指定多个
- `-i/--interface`: 要监控的网络接口（可选，默认自动选择）

### 示例
1. 监控单个目标：
```bash
python trigger.py -t 192.168.1.100
```

2. 监控多个目标：
```bash
python trigger.py -t 192.168.1.100 example.com
```

3. 指定网络接口：
```bash
python trigger.py -t 192.168.1.100 -i eth0
```

## 注意事项
1. 需要root权限运行
2. 依赖系统/proc文件系统和ss命令
3. 日志文件保存为network_trigger.log
4. 支持Linux系统

## 输出示例
```
INFO: 监听目标: 192.168.1.100
INFO: 解析IP: 192.168.1.100
INFO: [14:32:45] 匹配: 192.168.1.101:54321 -> 192.168.1.100 | 进程: curl (PID: 1234) | 用户: root
```

## 开发说明
- 使用scapy进行网络包捕获
- 使用psutil获取进程信息
- 支持自定义日志格式和颜色输出
- 提供详细的错误处理
