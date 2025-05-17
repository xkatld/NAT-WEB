import paramiko
import json
import os
from dotenv import load_dotenv

load_dotenv() # 加载 .env 文件中的环境变量

PVE_HOST = os.getenv("PVE_HOST")
PVE_SSH_PORT = int(os.getenv("PVE_SSH_PORT", 22))
PVE_SSH_USER = os.getenv("PVE_SSH_USER")
PVE_SSH_KEY_PATH = os.getenv("PVE_SSH_KEY_PATH")
PVE_SSH_PASSWORD = os.getenv("PVE_SSH_PASSWORD") # 如果使用密码

def run_ssh_command(command: str):
    """通过 SSH 连接 PVE 主机并执行命令"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if PVE_SSH_KEY_PATH:
            ssh.connect(PVE_HOST, port=PVE_SSH_PORT, username=PVE_SSH_USER, key_filename=PVE_SSH_KEY_PATH, timeout=10)
        elif PVE_SSH_PASSWORD:
             ssh.connect(PVE_HOST, port=PVE_SSH_PORT, username=PVE_SSH_USER, password=PVE_SSH_PASSWORD, timeout=10)
        else:
            raise ValueError("Must provide PVE_SSH_KEY_PATH or PVE_SSH_PASSWORD in .env")

        print(f"Executing command on {PVE_HOST}: {command}") # Debugging
        stdin, stdout, stderr = ssh.exec_command(command)

        # 读取输出
        stdout_str = stdout.read().decode('utf-8').strip()
        stderr_str = stderr.read().decode('utf-8').strip()

        # 检查是否有错误输出
        if stderr_str:
            # 有些命令可能有 stderr 但不是错误，例如 pvesh 的一些信息
            # 这里简单打印，实际应用需要更精细判断
             print(f"STDERR: {stderr_str}")

        # 检查退出码 (如果需要)
        # exit_code = stdout.channel.recv_exit_status()
        # if exit_code != 0:
        #     raise Exception(f"Command failed with exit code {exit_code}: {stderr_str}")

        return stdout_str, stderr_str

    except Exception as e:
        print(f"SSH command failed: {e}")
        raise # 抛出异常以便调用者处理
    finally:
        ssh.close()

def get_lxc_containers():
    """获取所有节点的 LXC 容器列表"""
    # 使用 pvesh 命令获取容器列表，输出为 JSON
    # pvesh get /cluster/resources --type lxc --output json
    command = "pvesh get /cluster/resources --type lxc --output json"
    try:
        stdout, stderr = run_ssh_command(command)
        # pvesh 的 json 输出可能有多行，需要解析整个字符串
        if stdout:
             # Pvesh 输出可能是 '[{},{}]' 格式的 JSON 数组
             return json.loads(stdout)
        return [] # 没有输出则返回空列表
    except Exception as e:
        print(f"Failed to get LXC containers: {e}")
        # 实际应用中这里应该返回一个错误响应
        return [] # 示例中简单返回空列表

def get_container_config(node: str, vmid: int):
    """获取特定容器的配置信息 (包括IP)"""
    # 使用 pvesh 获取容器配置，输出为 JSON
    command = f"pvesh get /nodes/{node}/lxc/{vmid}/config --output json"
    try:
        stdout, stderr = run_ssh_command(command)
        if stdout:
             # Pvesh 输出是单个 JSON 对象
             return json.loads(stdout)
        return None
    except Exception as e:
        print(f"Failed to get container config for {node}/{vmid}: {e}")
        return None

# 示例：获取所有容器及其IP (需要获取配置)
def get_containers_with_ips():
    containers = get_lxc_containers()
    containers_with_ips = []
    for container in containers:
        node = container.get('node')
        vmid = container.get('vmid')
        status = container.get('status')
        name = container.get('name')

        if node and vmid is not None:
            config = get_container_config(node, vmid)
            # 尝试从配置中提取IP地址
            # IP地址可能在 'net0' -> 'ip' 或 'net0' -> 'ip6' 字段
            ip_address = None
            if config and 'net0' in config:
                 net_config = config['net0']
                 # 示例只获取 IPv4，更复杂情况需要解析多个IP/CIDR
                 if 'ip' in net_config and net_config['ip'] != 'dhcp':
                     ip_address = net_config['ip'].split('/')[0] # 只取IP部分，去掉CIDR
                 elif 'ip' in net_config and net_config['ip'] == 'dhcp' and status == 'running':
                     # 对于 DHCP，需要检查运行中的容器，尝试获取当前分配的IP
                     # 这种方式更复杂，可能需要进入容器执行命令，或者依赖PVE API的dhcp信息 (不总是提供)
                     # 简单示例暂时不实现通过SSH进入容器获取DHCP IP
                     ip_address = "DHCP (Need running check)" # 标记需要运行时检查
                 # 考虑 IPv6
                 if 'ip6' in net_config and net_config['ip6'] != 'dhcp':
                      ip_address_v6 = net_config['ip6'].split('/')[0]
                      if ip_address: ip_address += f" ({ip_address_v6})"
                      else: ip_address = ip_address_v6
                 elif 'ip6' in net_config and net_config['ip6'] == 'dhcp' and status == 'running':
                      if ip_address: ip_address += " (DHCPv6)"
                      else: ip_address = "DHCPv6 (Need running check)"


            containers_with_ips.append({
                "vmid": vmid,
                "name": name,
                "node": node,
                "status": status,
                "ip_address": ip_address if ip_address else "N/A" # 如果获取不到IP
            })
        else:
             # 如果获取容器列表失败，打印原始数据
             print(f"Skipping container with missing node or vmid: {container}")

    return containers_with_ips


# 示例：添加 iptables NAT 规则 (未实现，仅作接口示例)
def add_iptables_dnat_rule(pve_ip: str, external_port: int, protocol: str, container_ip: str, internal_port: int):
    # 这是一个非常简化的示例，实际需要更复杂的规则管理和错误处理
    # 建议创建自定义链，而不是直接加到 PREROUTING
    # 并且需要确保 PVE 主机使用的是 iptables 而不是 nftables
    command = f"sudo iptables -t nat -A PREROUTING -p {protocol} -d {pve_ip} --dport {external_port} -j DNAT --to-destination {container_ip}:{internal_port}"
    try:
        stdout, stderr = run_ssh_command(command)
        if stderr:
            print(f"Error adding iptables rule: {stderr}")
            return False, stderr
        print(f"Successfully added iptables rule: {command}")
        # 实际应用中还需要保存规则到文件以便重启后生效
        # run_ssh_command("sudo iptables-save > /etc/iptables/rules.v4")
        return True, "Rule added successfully"
    except Exception as e:
        print(f"Exception adding iptables rule: {e}")
        return False, str(e)

# 示例：添加 nftables NAT 规则 (未实现，仅作接口示例)
# 需要检测 PVE 主机是使用 iptables 还是 nftables，并调用相应的函数
# def add_nftables_dnat_rule(...):
#     # nftables 命令更复杂，需要构建规则集
#     # command = f"sudo nft add rule ..."
#     pass
