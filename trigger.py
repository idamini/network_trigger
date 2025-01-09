#!/usr/bin/env python3
import os
import psutil
import argparse
import logging
import socket
from datetime import datetime
from scapy.all import sniff, IP
from scapy.layers.inet import TCP, UDP

# 配置日志
class ColorFormatter(logging.Formatter):
    """自定义带颜色的日志格式"""
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "%(levelname)s: %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: grey + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# 创建日志记录器
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# 文件处理器
file_handler = logging.FileHandler('network_trigger.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# 控制台处理器
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColorFormatter())

# 添加处理器
logger.addHandler(file_handler)
logger.addHandler(console_handler)

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="网络触发器 - 监控特定目标的网络请求并获取发起进程信息")
    
    parser.add_argument(
        "-t", "--target",
        required=True,
        nargs='+',
        help="要监控的目标地址（IP或域名），可指定多个"
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="要监控的网络接口（默认自动选择）"
    )
    
    return parser.parse_args()

def resolve_target(targets):
    """解析目标地址，返回所有IP地址列表"""
    ip_list = []
    for target in targets:
        try:
            # 如果是IP地址，直接添加
            try:
                socket.inet_aton(target)
                ip_list.append(target)
                continue
            except socket.error:
                pass
                
            # 解析域名
            addr_info = socket.getaddrinfo(target, None)
            ip_list.extend(info[4][0] for info in addr_info)
        except Exception as e:
            logger.error(f"解析失败: {target}")
    
    # 去重后返回
    return list(set(ip_list))

def get_process_info(pid):
    """获取进程信息"""
    try:
        process = psutil.Process(pid)
        return {
            "pid": pid,
            "name": process.name(),
            "cmdline": process.cmdline(),
            "username": process.username(),
            "create_time": process.create_time()
        }
    except psutil.NoSuchProcess:
        logger.warning(f"无法找到进程 {pid}，请检查权限")
        return None

def get_distro_info():
    """获取Linux发行版信息"""
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release') as f:
                info = {}
                for line in f:
                    if '=' in line:
                        k, v = line.strip().split('=', 1)
                        info[k] = v.strip('"')
                return info
        elif os.path.exists('/etc/redhat-release'):
            with open('/etc/redhat-release') as f:
                return {'ID': 'centos', 'VERSION_ID': f.read().strip()}
        return {}
    except Exception as e:
        logger.warning(f"获取发行版信息失败: {e}")
        return {}

def get_connection_pid(src_ip, src_port, proto):
    """
    根据源IP和端口获取进程ID
    支持TCP和UDP协议
    返回: 进程ID或None
    """
    try:
        distro = get_distro_info()
        distro_id = distro.get('ID', '').lower()
        
        # 通用Linux实现
        src_port_hex = f"{src_port:04X}"
        proc_file = "/proc/net/tcp" if proto == 6 else "/proc/net/udp"
        
        # 检查/proc/net文件是否存在
        if not os.path.exists(proc_file):
            logger.warning(f"无法访问 {proc_file}，尝试使用ss命令")
            raise FileNotFoundError(proc_file)
        
        with open(proc_file, 'r') as f:
            next(f)  # 跳过标题行
            for line in f:
                fields = line.strip().split()
                if len(fields) < 10:
                    continue
                    
                local_addr = fields[1]
                local_ip_hex, local_port_hex = local_addr.split(':')
                
                # 转换IP地址
                try:
                    local_ip = '.'.join(str(int(local_ip_hex[i:i+2], 16)) 
                                     for i in range(0, 8, 2)[::-1])
                except ValueError:
                    continue
                
                # 检查IP和端口是否匹配
                if local_ip == src_ip and local_port_hex == src_port_hex:
                    inode = int(fields[9])
                    
                    # 遍历所有进程
                    for proc in os.listdir('/proc'):
                        if not proc.isdigit():
                            continue
                            
                        try:
                            # 检查进程的fd目录
                            fd_path = f'/proc/{proc}/fd'
                            if not os.path.exists(fd_path):
                                continue
                                
                            for fd in os.listdir(fd_path):
                                try:
                                    link = os.readlink(f'{fd_path}/{fd}')
                                    if f'socket:[{inode}]' in link:
                                        return int(proc)
                                except (FileNotFoundError, OSError):
                                    continue
                        except (FileNotFoundError, OSError):
                            continue
                            
        # 如果没找到，尝试使用ss命令
        try:
            import subprocess
            # 检查ss命令是否存在
            if not any(os.access(os.path.join(path, 'ss'), os.X_OK) for path in os.environ['PATH'].split(os.pathsep)):
                logger.warning("ss命令不可用")
                return None
                
            cmd = ['ss', '-tunp' if proto == 6 else '-uunp']
            output = subprocess.check_output(cmd).decode()
            
            for line in output.splitlines():
                if f'{src_ip}:{src_port}' in line and 'users:' in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith('pid='):
                            return int(part.split('=')[1].split(',')[0])
        except subprocess.CalledProcessError as e:
            logger.error(f"执行ss命令失败: {e}")
        except Exception as e:
            logger.error(f"使用ss命令时出错: {e}")
            
    except FileNotFoundError as e:
        logger.error(f"无法访问系统文件: {e}")
    except Exception as e:
        logger.error(f"获取进程ID时出错: {e}")
    
    return None

def packet_handler(packet):
    """处理捕获的网络包"""
    if IP in packet:
        ip_packet = packet[IP]
        
        # 检查目标IP是否匹配
        if ip_packet.dst in target_ips:
            # 获取源IP和端口
            src_ip = ip_packet.src
            src_port = None
            
            if TCP in packet:
                src_port = packet[TCP].sport
                proto = 6  # TCP
            elif UDP in packet:
                src_port = packet[UDP].sport
                proto = 17  # UDP
            
            if src_port:
                # 获取进程ID
                pid = get_connection_pid(src_ip, src_port, proto)
                if pid:
                    process_info = get_process_info(pid)
                    if process_info:
                        logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] 匹配: {src_ip}:{src_port} -> {ip_packet.dst} | 进程: {process_info['name']} (PID: {process_info['pid']}) | 用户: {process_info['username']}")
                    else:
                        logger.warning(f"无法获取进程 {pid} 的信息，请检查权限")
                else:
                    logger.warning("无法找到发起请求的进程，请确保ss命令可用")

def main():
    global target_ips, args
    args = parse_args()
    target_ips = resolve_target(args.target)
    
    if not target_ips:
        logger.error(f"解析失败: {' '.join(args.target)}")
        return
        
    logger.info(f"监听目标: {' '.join(args.target)}")
    logger.info(f"解析IP: {', '.join(target_ips)}")
    try:
        sniff(iface=args.interface, prn=packet_handler, store=False)
    except PermissionError:
        logger.error("需要root权限才能捕获网络包，请使用sudo运行")
    except Exception as e:
        logger.error(f"捕获网络包失败: {e}")

if __name__ == "__main__":
    main()
