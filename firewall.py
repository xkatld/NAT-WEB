import subprocess
import sys
import time

NAT_CHAIN = "PVE_LXC_NAT"
RULE_COMMENT_PREFIX = "pvelxcnat:"

def _run_command(cmd):
    print(f"正在执行命令：{' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"错误：命令未找到。请确保系统中安装了 iptables、pct 和 sudo，并且它们在 PATH 环境变量中。", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败，退出码 {e.returncode}", file=sys.stderr)
        print("STDOUT:", e.stdout.strip(), file=sys.stderr)
        print("STDERR:", e.stderr.strip(), file=sys.stderr)

        if e.stderr and "Chain already exists" in e.stderr:
            print("信息：iptables 链已存在。")
        elif e.stderr and "No chain/target/match by that name" in e.stderr:
             print("信息：iptables 链不存在。")

        return None
    except subprocess.TimeoutExpired:
        print(f"错误：命令超时。", file=sys.stderr)
        return None
    except Exception as e:
        print(f"发生未知错误：{e}", file=sys.stderr)
        return None

def _ensure_nat_chain():
    print(f"确保 iptables 链 '{NAT_CHAIN}' 存在...")

    create_cmd = ["sudo", "iptables", "-N", NAT_CHAIN]
    print(f"尝试创建链：{' '.join(create_cmd)}")
    try:
        subprocess.run(create_cmd, capture_output=True, text=True, check=True, timeout=5)
        print(f"链 '{NAT_CHAIN}' 创建成功。")
    except subprocess.CalledProcessError as e:
        if e.stderr and "Chain already exists" in e.stderr:
            print(f"信息：iptables 链 '{NAT_CHAIN}' 已存在。")
        else:
            print(f"创建链 '{NAT_CHAIN}' 时出错（退出码 {e.returncode}）：{e.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
    except FileNotFoundError:
        print(f"错误：未找到 iptables 命令。", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"错误：创建链时超时。", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"创建链时发生未知错误：{e}", file=sys.stderr)
        sys.exit(1)

    print(f"检查从 PREROUTING 到 {NAT_CHAIN} 的跳转规则...")
    list_cmd = ["sudo", "iptables", "-S", "PREROUTING"]
    existing_rules_output = _run_command(list_cmd)

    jump_rule_spec = f"-A PREROUTING -j {NAT_CHAIN}"

    if existing_rules_output is None:
         print("错误：无法检索现有 PREROUTING 规则。无法验证/添加跳转规则。防火墙同步可能不完整。", file=sys.stderr)
    elif jump_rule_spec not in existing_rules_output.splitlines():
        print(f"添加跳转规则到 PREROUTING -> {NAT_CHAIN}...")
        add_jump_cmd = ["sudo", "iptables", "-I", "PREROUTING", "-j", NAT_CHAIN]
        if _run_command(add_jump_cmd) is None:
             print(f"错误添加跳转规则：{' '.join(add_jump_cmd)}", file=sys.stderr)
             print("防火墙同步可能不完整。", file=sys.stderr)
        else:
             print("跳转规则添加成功。")
    else:
        print("跳转规则已存在。")


def _clear_nat_chain():
    print(f"清空自定义 NAT 链 '{NAT_CHAIN}' 中的所有规则...")
    flush_cmd = ["sudo", "iptables", "-F", NAT_CHAIN]
    if _run_command(flush_cmd) is None:
         print(f"清空链 '{NAT_CHAIN}' 时出错：{' '.join(flush_cmd)}", file=sys.stderr)
         print("现有 NAT 规则可能未被移除。", file=sys.stderr)
    else:
        print(f"链 '{NAT_CHAIN}' 已清空。")


def _get_lxc_ip(lxc_id):
    print(f"获取 LXC {lxc_id} 的 IP 地址...")
    cmd = ["sudo", "pct", "exec", str(lxc_id), "--", "ip", "-4", "-brief", "addr", "show", "eth0"]
    output = _run_command(cmd)

    if output:
        parts = output.split()
        if len(parts) >= 3 and 'inet' not in parts:
             try:
                ip_with_mask = parts[2]
                ip = ip_with_mask.split('/')[0]
                print(f"找到 LXC {lxc_id} 的 IP：{ip} (简洁输出)。")
                return ip
             except (ValueError, IndexError):
                 print(f"无法解析简洁 IP 行：{output}", file=sys.stderr)
                 return None
        else:
             print(f"尝试解析 LXC {lxc_id} 的完整 ip addr 输出...")
             cmd_full = ["sudo", "pct", "exec", str(lxc_id), "--", "ip", "-4", "addr", "show", "eth0"]
             output_full = _run_command(cmd_full)
             if output_full:
                 for line in output_full.splitlines():
                     if ' inet ' in line:
                         parts = line.split()
                         try:
                            inet_index = parts.index('inet')
                            ip_with_mask = parts[inet_index + 1]
                            ip = ip_with_mask.split('/')[0]
                            print(f"找到 LXC {lxc_id} 的 IP：{ip} (完整输出解析)。")
                            return ip
                         except (ValueError, IndexError):
                            print(f"无法解析完整 IP 行：{line}", file=sys.stderr)
                 print(f"未在 LXC {lxc_id} 的 eth0 上找到 IPv4 地址。", file=sys.stderr)
             else:
                 print(f"无法获取 LXC {lxc_id} 的完整网络信息。", file=sys.stderr)

    print(f"无法获取 LXC {lxc_id} 的 IP。", file=sys.stderr)
    return None


def _build_iptables_rule_cmd(rule, container_ip):
    base_cmd = [
        "sudo", "iptables", "-A", NAT_CHAIN,
        "-d", rule['external_ip'],
        "--dport", str(rule['external_port']),
        "-j", "DNAT",
        "--to-destination", f"{container_ip}:{rule['container_port']}",
        "-m", "comment", "--comment", f"{RULE_COMMENT_PREFIX}{rule['id']}"
    ]

    commands = []
    protocol = rule['protocol'].lower()

    if protocol == 'tcp' or protocol == 'both':
        cmd_tcp = base_cmd[:]
        cmd_tcp.insert(cmd_tcp.index("--dport"), "-p")
        cmd_tcp.insert(cmd_tcp.index("-p") + 1, "tcp")
        commands.append(cmd_tcp)

    if protocol == 'udp' or protocol == 'both':
        cmd_udp = base_cmd[:]
        cmd_udp.insert(cmd_udp.index("--dport"), "-p")
        cmd_udp.insert(cmd_udp.index("-p") + 1, "udp")
        commands.append(cmd_udp)

    return commands


def apply_all_rules(rules_from_db):
    print("\n--- 正在应用所有已启用规则 ---")
    _ensure_nat_chain()
    _clear_nat_chain()

    success_count = 0
    failed_count = 0
    errors = []

    enabled_rules = [rule for rule in rules_from_db if rule['enabled']]

    if not enabled_rules:
        print("没有需要应用的已启用规则。")
        print("--- 规则应用完成 ---\n")
        return 0, 0, []

    print(f"找到 {len(enabled_rules)} 条需要应用的已启用规则。")

    for rule in enabled_rules:
        print(f"应用规则 ID {rule['id']} (LXC {rule['lxc_id']} 外部端口:{rule['external_port']}/{rule['protocol']} -> 容器端口:{rule['container_port']})...")
        container_ip = _get_lxc_ip(rule['lxc_id'])

        if container_ip:
            commands = _build_iptables_rule_cmd(rule, container_ip)
            applied_successfully = True
            if not commands:
                applied_successfully = False
                errors.append(f"规则 ID {rule['id']} 生成命令失败 (协议错误?)。")
            else:
                for cmd in commands:
                    if _run_command(cmd) is None:
                        applied_successfully = False
                        errors.append(f"应用规则 ID {rule['id']} 的命令失败：{' '.join(cmd)}")
                        break
            if applied_successfully:
                success_count += 1
            else:
                failed_count += 1
        else:
            failed_count += 1
            errors.append(f"无法获取 LXC {rule['lxc_id']} 的 IP (规则 ID {rule['id']})。规则未应用。")
        print("-" * 20)

    print(f"--- 规则应用完成。成功：{success_count}，失败：{failed_count} ---\n")
    return success_count, failed_count, errors
