from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess
import json
import sqlite3
import datetime
import os
import time
import re
import shlex
import sys
import logging

app = Flask(__name__)
DATABASE_NAME = 'incus_manager.db' # Renaming DB might be good, but keep for compatibility with original request
PVE_NODE = os.environ.get('PVE_NODE', 'localhost') # Configure your PVE node name here
PVE_STORAGE = os.environ.get('PVE_STORAGE', 'local') # Configure your PVE storage name for templates here

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app.logger.setLevel(logging.INFO)

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        app.logger.debug(f"DB Query: {query} with args {args}")
        cur.execute(query, args)
        if not query.strip().upper().startswith('SELECT'):
             conn.commit()
        rv = cur.fetchall()
        app.logger.debug(f"DB Query Result count: {len(rv)}")
    except sqlite3.Error as e:
        app.logger.error(f"数据库查询错误: {e}\nQuery: {query}\nArgs: {args}")
        rv = []
        if conn:
             conn.rollback()
    finally:
        if conn:
            conn.close()
    return (rv[0] if rv else None) if one else rv

def _run_subprocess_command(command_parts, parse_json=True, timeout=60):
    """Generic function to run any subprocess command."""
    try:
        # Ensure consistent locale for command output parsing
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        env_vars['LANG'] = 'C.UTF-8'

        log_command = ' '.join(shlex.quote(part) for part in command_parts)
        app.logger.info(f"Executing command: {log_command}")

        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=timeout, env=env_vars)

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            app.logger.error(f"Command failed (Exit code {result.returncode}): {log_command}\nError: {error_message}")
            return False, error_message
        else:
             app.logger.debug(f"Command success: {log_command}")
             if parse_json:
                 try:
                    output_text = result.stdout.strip()
                    # Some commands might output BOM, strip it
                    if output_text.startswith(u'\ufeff'):
                        output_text = output_text[1:]
                    # Check if output is empty or just whitespace before parsing
                    if not output_text:
                         return True, None # Successful command with no JSON output
                    return True, json.loads(output_text)
                 except json.JSONDecodeError as e:
                    app.logger.error(f"Failed to parse JSON from command output: {result.stdout.strip()}\nError: {e}")
                    return False, f"解析命令输出为 JSON 失败: {e}\n原始输出: {result.stdout.strip()}"
             else:
                 return True, result.stdout.strip()

    except FileNotFoundError:
        command_name = command_parts[0] if command_parts else 'command'
        app.logger.error(f"Command not found: {command_name}. Is it installed and in PATH?")
        return False, f"命令 '{command_name}' 未找到。请确保它已安装并在系统 PATH 中。"
    except subprocess.TimeoutExpired:
        app.logger.error(f"Command timed out (>{timeout}s): {log_command}")
        return False, f"命令执行超时 (>{timeout}秒)。"
    except Exception as e:
        app.logger.error(f"执行命令时发生异常: {e}")
        return False, f"执行命令时发生异常: {str(e)}"

def run_pvesh_command(command_args, parse_json=True, timeout=60):
    """Run a pvesh command, assuming JSON output for parse_json=True."""
    full_command = ['pvesh'] + command_args
    if parse_json and '--output-format' not in command_args:
         full_command.extend(['--output-format', 'json'])

    # Inject node path if it looks like a node-specific API path
    # Simple heuristic: if the first arg is 'get', 'ls', 'create', 'set', 'delete' and the path doesn't start with /cluster or /nodes/{node}
    if len(command_args) > 1 and command_args[0] in ['get', 'ls', 'create', 'set', 'delete']:
        api_path_index = 1 # Assumes path is the second argument
        api_path = command_args[api_path_index]
        if api_path.startswith('/') and not api_path.startswith('/cluster') and not api_path.startswith(f'/nodes/{PVE_NODE}'):
             # Attempt to prepend node path unless it's already node-specific or cluster-wide
             # This heuristic might need refinement for complex pvesh usage
             # For /lxc/{vmid}, /qemu/{vmid}, etc., we need /nodes/{node}/...
             # A better approach might be to explicitly pass the full API path including /nodes/{node}
             # Let's adjust: the caller should provide the full path like /nodes/{node}/lxc
             pass # The caller should construct the path correctly
    elif len(command_args) > 0 and command_args[0] in ['nodes', 'storage', 'cluster']:
         # Special case for root-level commands like 'pvesh nodes'
         pass
    # Add --node explicitly for commands that need it if not already there
    # Note: --node is not always applicable, better rely on API path /nodes/{node}
    # if '--node' not in full_command and command_args[0] not in ['help', 'usage', 'nodes', 'storage', 'cluster']:
    #     full_command.extend(['--node', PVE_NODE]) # This is often wrong, rely on API path

    return _run_subprocess_command(full_command, parse_json, timeout)

def run_pct_command(command_args, parse_json=False, timeout=60):
    """Run a pct command."""
    full_command = ['pct'] + command_args
    return _run_subprocess_command(full_command, parse_json, timeout)

def get_vmid_from_name(name):
    """Lookup VMID by name in the database."""
    try:
        container = query_db('SELECT vmid FROM containers WHERE name = ?', [name], one=True)
        if container:
            return True, container['vmid']
        else:
            app.logger.warning(f"Container name '{name}' not found in DB.")
            return False, f"数据库中找不到名称为 '{name}' 的容器记录。"
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 get_vmid_from_name for {name}: {e}")
        return False, f"从数据库查找VMID失败: {e}"


def sync_container_to_db(vmid, name, ostemplate, status, ip):
    """Sync or add container info to DB based on VMID."""
    try:
        query_db('''
            INSERT INTO containers (vmid, name, ostemplate, status, ip, last_synced)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(vmid) DO UPDATE SET
                name = excluded.name,
                ostemplate = excluded.ostemplate,
                status = excluded.status,
                ip = excluded.ip,
                last_synced = CURRENT_TIMESTAMP
        ''', (vmid, name, ostemplate, status, ip))
        # Handle potential conflict on 'name' unique constraint if VMID changed for a name (shouldn't happen with PVE)
        # Or if a container with the same name exists under a different VMID (should also not happen)
        # If the DB `name` column has a UNIQUE constraint, this might fail if a new container gets the same name as an old, deleted one not cleaned from DB.
        # The `ON CONFLICT(vmid)` handles the primary key.
        # Let's add a step to update the name if a conflict occurs on name but not vmid (unlikely scenario but safer)
        # A cleaner schema relies purely on vmid as the primary identifier. Name is secondary.
        # The unique constraint should probably be on vmid, not name in the DB schema.
        # Let's assume vmid is PK and name is just a column for lookup, allowing non-unique names if PVE allowed (it doesn't strictly enforce unique hostname globally, but unique VMID)
        # Correcting based on common PVE use: Name is usually unique per node for display. VMID is unique globally. Let's keep UNIQUE on name for lookup convenience, but VMID is PK. This means if two containers *could* have the same name, the DB schema prevents it. PVE prevents this on a node via hostname.

    except sqlite3.IntegrityError as e:
        # This usually happens on the UNIQUE constraint for 'name' if a container exists in DB with the same name but different VMID
        app.logger.error(f"数据库完整性错误 sync_container_to_db for VMID {vmid} name '{name}': {e}")
        # Attempt to update based on name if VMID conflict didn't happen but name conflict did?
        # This is tricky. The ON CONFLICT(vmid) handles the main case. A name conflict suggests a logic error or stale DB entry.
        # For now, log and fail sync for this entry.
        # query_db('UPDATE containers SET vmid = ?, status = ?, ostemplate = ?, ip = ?, last_synced = CURRENT_TIMESTAMP WHERE name = ?', (vmid, status, ostemplate, ip, name))
        # app.logger.warning(f"Attempted to update container by name '{name}' due to IntegrityError: {e}")
        pass # Relying on ON CONFLICT(vmid) is the primary sync mechanism
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 sync_container_to_db for VMID {vmid} name '{name}': {e}")


def remove_container_from_db(vmid):
    """Remove container and associated NAT rules from DB by VMID."""
    try:
        query_db('DELETE FROM nat_rules WHERE vmid = ?', [vmid])
        query_db('DELETE FROM containers WHERE vmid = ?', [vmid])
        app.logger.info(f"从数据库中移除了VMID {vmid} 及其NAT规则记录。")
    except sqlite3.Error as e:
         app.logger.error(f"数据库错误 remove_container_from_db for VMID {vmid}: {e}")

def _get_container_raw_info(vmid):
    """Get raw container info from PVE (status and config)."""
    if vmid is None:
        return None, "VMID 未提供。"

    status_data = None
    config_data = None
    error_message = None

    success_status, status_output = run_pvesh_command(['get', f'/nodes/{PVE_NODE}/lxc/{vmid}/status'])
    if success_status and isinstance(status_output, dict):
        status_data = status_output
    else:
        error_message = f"无法获取 VMID {vmid} 的状态信息: {status_output}"
        app.logger.error(error_message)
        # Try getting config even if status failed
        # return None, error_message # Or continue to get config? Let's get config too if possible.

    success_config, config_output = run_pvesh_command(['get', f'/nodes/{PVE_NODE}/lxc/{vmid}/config'])
    if success_config and isinstance(config_output, dict):
        config_data = config_output
    else:
        if error_message: # Append config error if status also failed
             error_message += f"; 无法获取配置信息: {config_output}"
        else:
             error_message = f"无法获取 VMID {vmid} 的配置信息: {config_output}"
             app.logger.error(error_message)


    if status_data is None and config_data is None:
         return None, error_message or f"无法从 PVE 获取 VMID {vmid} 的状态或配置信息。"

    # Combine and structure data
    info_output = {
        'vmid': vmid,
        'name': config_data.get('hostname', status_data.get('name', str(vmid))) if config_data else status_data.get('name', str(vmid)), # Use hostname from config if available
        'status': status_data.get('status', 'Unknown') if status_data else config_data.get('status', 'Unknown'), # PVE config also has a status field sometimes
        'type': 'lxc', # Hardcoded for this adaptation
        'ostemplate': config_data.get('ostemplate', 'N/A') if config_data else 'N/A',
        'memory': config_data.get('memory', 'N/A') if config_data else 'N/A',
        'cores': config_data.get('cores', 'N/A') if config_data else 'N/A',
        'rootfs': config_data.get('rootfs', 'N/A') if config_data else 'N/A',
        'net': config_data.get('net0', 'N/A') if config_data else 'N/A', # Get first network device config
        'ip': 'N/A',
        'live_data_available': True if status_data else False,
        'message': '数据主要来自 PVE 实时信息。',
        'pve_status_raw': status_data, # Include raw data for debugging/completeness
        'pve_config_raw': config_data,
        'errors': error_message # Report any errors encountered
    }

    # Extract IP address from status data if available and running
    if status_data and status_data.get('status') == 'running':
         # PVE status output often has 'ha.stat.ip' or 'vm.ip' or similar, or it might be in 'agent.network-get-interfaces' output
         # For simplicity, let's try to get it from the initial ls sync data if available, or add a pct exec ip addr show call?
         # pct exec <vmid> ip -4 addr show scope global dev eth0 | grep inet | awk '{print $2}' | cut -d/ -f1
         success_ip, ip_output = run_pct_command([str(vmid), 'exec', '--', 'ip', '-4', 'addr', 'show', 'scope', 'global', 'dev', 'eth0'], parse_json=False, timeout=5)
         if success_ip:
             match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_output)
             if match:
                 info_output['ip'] = match.group(1)
             else:
                 app.logger.warning(f"Could not parse IP from 'pct exec {vmid} ip addr show': {ip_output}")
                 info_output['ip'] = 'N/A (Parse Failed)'
         else:
             app.logger.warning(f"Failed to get IP using 'pct exec {vmid} ip addr show': {ip_output}")
             info_output['ip'] = 'N/A (Exec Failed)'

    # Fallback/Supplement from DB if live data extraction failed or incomplete
    if status_data is None or config_data is None:
        db_info = query_db('SELECT * FROM containers WHERE vmid = ?', [vmid], one=True)
        if db_info:
             info_output.update({
                 'vmid': db_info['vmid'],
                 'name': db_info.get('name', info_output.get('name', str(vmid))),
                 'status': db_info.get('status', info_output.get('status', 'Unknown')),
                 'ostemplate': db_info.get('ostemplate', info_output.get('ostemplate', 'N/A')),
                 'ip': db_info.get('ip', info_output.get('ip', 'N/A')),
                 'last_synced': db_info.get('last_synced'),
                 'live_data_available': info_output['live_data_available'], # Keep True if status/config was partial
                 'message': (info_output['message'] + " 数据不足，辅以数据库信息。") if (status_data is None or config_data is None) else info_output['message'],
                 # Note: Other fields like memory, cores, rootfs, net config might not be in DB sync from ls
                 # These will remain 'N/A' if live config data wasn't fetched.
             })
        else:
            info_output['message'] += " 数据库中无记录，且无法从 PVE 获取实时信息。"
            # If both PVE live and DB failed completely, return None
            if status_data is None and config_data is None and db_info is None:
                return None, error_message or f"无法获取 VMID {vmid} 的任何信息 (PVE和数据库)。"


    return info_output, None

def perform_iptables_add(rule_details):
    """Adds an iptables NAT rule."""
    if not isinstance(rule_details, dict):
        return False, "Invalid rule details provided for iptables addition."

    required_keys = ['host_port', 'container_port', 'protocol', 'ip_at_creation']
    if not all(key in rule_details for key in required_keys):
        return False, f"Missing required keys in rule details for iptables addition. Requires: {required_keys}"

    try:
        host_port = rule_details['host_port']
        container_port = rule_details['container_port']
        protocol = rule_details['protocol']
        ip_at_creation = rule_details['ip_at_creation'] # IP used at the time of rule creation

        iptables_command = [
            'iptables',
            '-t', 'nat',
            '-A', 'PREROUTING',
            '-p', protocol,
            '--dport', str(host_port),
            '-j', 'DNAT',
            '--to-destination', f'{ip_at_creation}:{container_port}'
        ]

        app.logger.info(f"Executing iptables add for rule: {' '.join(shlex.quote(part) for part in iptables_command)}")

        success, output = _run_subprocess_command(iptables_command, parse_json=False, timeout=10)

        if success:
             app.logger.info(f"iptables add successful for rule host={host_port}/{protocol} to container={ip_at_creation}:{container_port}.")
             return True, f"成功添加 iptables 规则 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation})."
        else:
             app.logger.error(f"iptables add failed for rule host={host_port}/{protocol} to container={ip_at_creation}:{container_port}: {output}")
             return False, f"添加 iptables 规则失败 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation}): {output}"

    except Exception as e:
        app.logger.error(f"Exception during perform_iptables_add: {e}")
        return False, f"执行 iptables 添加命令时发生异常: {str(e)}"


def perform_iptables_delete_for_rule(rule_details):
    """Deletes an iptables NAT rule based on stored details."""
    if not isinstance(rule_details, dict):
        return False, "Invalid rule details provided for iptables deletion.", False

    required_keys = ['host_port', 'container_port', 'protocol', 'ip_at_creation']
    if not all(key in rule_details for key in required_keys):
        return False, f"Missing required keys in rule details for iptables deletion. Requires: {required_keys}", False

    try:
        host_port = rule_details['host_port']
        container_port = rule_details['container_port']
        protocol = rule_details['protocol']
        ip_at_creation = rule_details['ip_at_creation'] # Use the IP recorded when the rule was added

        iptables_command = [
            'iptables',
            '-t', 'nat',
            '-D', 'PREROUTING',
            '-p', protocol,
            '--dport', str(host_port),
            '-j', 'DNAT',
            '--to-destination', f'{ip_at_creation}:{container_port}'
        ]

        app.logger.info(f"Executing iptables delete for rule ID {rule_details.get('id', 'N/A')}: {' '.join(shlex.quote(part) for part in iptables_command)}")

        success, output = _run_subprocess_command(iptables_command, parse_json=False, timeout=10)

        if success:
             app.logger.info(f"iptables delete successful for rule ID {rule_details.get('id', 'N/A')}.")
             return True, f"成功从 iptables 移除规则 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation}).", False
        else:
             # Check for specific "Bad rule" or "No chain/target/match by that name" errors which indicate the rule wasn't found
             is_bad_rule_or_not_found = any(err in output for err in ["Bad rule", "No chain/target/match by that name", "No such file or directory"])
             app.logger.error(f"iptables delete failed for rule ID {rule_details.get('id', 'N/A')}: {output}. Is Bad Rule/Not Found: {is_bad_rule_or_not_found}")
             return False, f"从 iptables 移除规则失败 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation}): {output}", is_bad_rule_or_not_found

    except Exception as e:
        app.logger.error(f"Exception during perform_iptables_delete_for_rule for rule ID {rule_details.get('id', 'N/A')}: {e}")
        return False, f"执行 iptables 删除命令时发生异常: {str(e)}", False


def check_nat_rule_exists_in_db(vmid, host_port, protocol):
    """Check if a NAT rule exists in DB for a given VMID, host port, and protocol."""
    try:
        rule = query_db('''
            SELECT id FROM nat_rules
            WHERE vmid = ? AND host_port = ? AND protocol = ?
        ''', (vmid, host_port, protocol), one=True)
        return True, rule is not None
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 check_nat_rule_exists_in_db for VMID {vmid}, host={host_port}/{protocol}: {e}")
        return False, f"检查规则记录失败: {e}"


def add_nat_rule_to_db(rule_details):
    """Add a NAT rule record to the database."""
    try:
        query_db('''
            INSERT INTO nat_rules (vmid, host_port, container_port, protocol, ip_at_creation)
            VALUES (?, ?, ?, ?, ?)
        ''', (rule_details['vmid'], rule_details['host_port'],
              rule_details['container_port'], rule_details['protocol'],
              rule_details['ip_at_creation']))
        inserted_row = query_db('SELECT last_insert_rowid()', one=True)
        rule_id = inserted_row[0] if inserted_row else None
        app.logger.info(f"Added NAT rule to DB: ID {rule_id}, VMID {rule_details['vmid']}, host={rule_details['host_port']}/{rule_details['protocol']}, container={rule_details['ip_at_creation']}:{rule_details['container_port']}")
        return True, rule_id
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 add_nat_rule_to_db for VMID {rule_details.get('vmid', 'N/A')}: {e}")
        return False, f"添加规则记录到数据库失败: {e}"

def get_nat_rules_for_container(vmid):
    """Get NAT rules from DB for a specific VMID."""
    try:
        rules = query_db('SELECT id, vmid, host_port, container_port, protocol, ip_at_creation, created_at FROM nat_rules WHERE vmid = ?', [vmid])
        return True, [dict(row) for row in rules]
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 get_nat_rules_for_container for VMID {vmid}: {e}")
        return False, f"从数据库获取规则失败: {e}"

def get_nat_rule_by_id(rule_id):
    """Get a specific NAT rule from DB by its ID."""
    try:
        rule = query_db('SELECT id, vmid, host_port, container_port, protocol, ip_at_creation FROM nat_rules WHERE id = ?', [rule_id], one=True)
        return True, dict(rule) if rule else None
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 get_nat_rule_by_id for id {rule_id}: {e}")
        return False, f"从数据库获取规则 (ID {rule_id}) 失败: {e}"


def remove_nat_rule_from_db(rule_id):
    """Remove a specific NAT rule record from the database by its ID."""
    try:
        query_db('DELETE FROM nat_rules WHERE id = ?', [rule_id])
        app.logger.info(f"Removed NAT rule record from DB: ID {rule_id}")
        return True, "规则记录成功从数据库移除。"
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 remove_nat_rule_from_db for id {rule_id}: {e}")
        return False, f"从数据库移除规则记录失败: {e}"

def cleanup_orphaned_nat_rules_in_db(existing_pve_vmids):
    """Remove NAT rules from DB whose associated VMID no longer exists in PVE."""
    try:
        db_rule_vmids_rows = query_db('SELECT DISTINCT vmid FROM nat_rules')
        db_rule_vmids = {row['vmid'] for row in db_rule_vmids_rows}

        orphaned_vmids = [
            vmid for vmid in db_rule_vmids
            if vmid not in existing_pve_vmids
        ]

        if orphaned_vmids:
            app.logger.warning(f"检测到数据库中存在孤立的NAT规则记录，对应的VMID已不存在于PVE: {orphaned_vmids}")
            placeholders = ','.join('?' * len(orphaned_vmids))
            query = f'DELETE FROM nat_rules WHERE vmid IN ({placeholders})'
            query_db(query, orphaned_vmids)
            app.logger.info(f"已从数据库中移除 {len(orphaned_vmids)} 个孤立VMID的NAT规则记录。")
            # Also clean up containers table entries that might be stale
            container_query = f'DELETE FROM containers WHERE vmid IN ({placeholders})'
            query_db(container_query, orphaned_vmids)
            app.logger.info(f"已从数据库中移除 {len(orphaned_vmids)} 个孤立VMID的容器记录 (如果存在)。")

    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 cleanup_orphaned_nat_rules_in_db: {e}")
    except Exception as e:
        app.logger.error(f"清理孤立NAT规则时发生异常: {e}")


@app.route('/')
def index():
    """Lists LXC containers and OS templates."""
    listed_containers = []
    available_templates = []
    pve_container_error = False
    pve_container_error_message = None
    pve_template_error = False
    pve_template_error_message = None

    # --- List Containers ---
    # Use /nodes/{node}/lxc for listing LXC containers
    success_list, containers_data = run_pvesh_command(['ls', f'/nodes/{PVE_NODE}/lxc']) # pvesh ls defaults to json format

    db_containers_dict = {}
    try:
        # Fetch existing containers from DB to display if PVE call fails, or for orphaned cleanup
        db_containers_dict = {row['vmid']: dict(row) for row in query_db('SELECT * FROM containers')}
    except sqlite3.OperationalError as e:
        app.logger.error(f"数据库表 'containers' 可能不存在: {e}. 请运行 init_db.py.")
        pve_container_error = True
        pve_container_error_message = f"数据库错误：容器表未找到，请运行 init_db.py。原始错误: {e}"
        containers_data = [] # Prevent processing potentially bad data

    pve_container_vmids_set = set()

    if not success_list:
        pve_container_error = True
        pve_container_error_message = containers_data # Error message from run_pvesh_command
        app.logger.warning(f"无法从 PVE 获取容器列表 ({pve_container_error_message})，尝试从数据库加载。")
        # Load from DB if PVE list failed
        for vmid, data in db_containers_dict.items():
            listed_containers.append({
                'vmid': vmid,
                'name': data.get('name', f'VMID {vmid} (DB)'),
                'status': data.get('status', 'Unknown (from DB)'),
                'ostemplate': data.get('ostemplate', 'N/A (from DB)'),
                'ip': data.get('ip', 'N/A (DB info)')
            })

    elif isinstance(containers_data, list):
        for item in containers_data:
            if not isinstance(item, dict) or 'vmid' not in item:
                app.logger.warning(f"Skipping invalid item in containers_data from PVE: {item}")
                continue

            vmid = item.get('vmid')
            if vmid is None: continue # VMID is essential

            pve_container_vmids_set.add(vmid)

            # Extract relevant fields from PVE ls output
            container_info = {
                'vmid': vmid,
                'name': item.get('name', f'VMID {vmid}'), # 'name' might be hostname
                'status': item.get('status', 'unknown'),
                'ostemplate': item.get('template', 'N/A'), # 'template' field in ls output? or 'ostemplate' in config? Check pvesh ls output. Let's assume 'template' is available or default N/A. Actually, ls shows 'name', 'vmid', 'status', 'ip', etc. Config has ostemplate. Let's use N/A here and rely on config for info page. *Correction:* PVE `ls` output for LXC often includes `template` if created from one, or `ostemplate`? Let's assume it's `template` or fallback. Looking at `pvesh ls /nodes/{node}/lxc` output structure... it often includes `vmid`, `name`, `status`, `ip`, `uptime`, `type`. Template is NOT in `ls`. We must get it from config or store it from creation. Let's store from creation and sync from config on info page. For the list, just display N/A or lookup from DB. Use DB value if exists.
                'ip': item.get('ip', 'N/A'), # IP is often in ls output if running
            }
            # Use DB ostemplate if available, otherwise 'N/A'
            db_entry = db_containers_dict.get(vmid)
            if db_entry:
                 container_info['ostemplate'] = db_entry.get('ostemplate', 'N/A (DB)')
                 # Use DB name as primary if available, fallback to PVE 'name' which might be hostname
                 container_info['name'] = db_entry.get('name', item.get('name', f'VMID {vmid}'))
                 # Prioritize live status/IP from PVE ls
                 container_info['status'] = item.get('status', container_info['status'])
                 container_info['ip'] = item.get('ip', container_info['ip'])


            listed_containers.append(container_info)
            # Sync to DB. Note: ostemplate and created_at are not reliably in `pvesh ls`.
            # ostemplate will be synced during creation, or if _get_container_raw_info is called.
            # Let's refine sync_container_to_db to handle update gracefully, maybe only syncing status/ip from ls.
            # Or fetch config here? No, too slow.
            sync_container_to_db(container_info['vmid'], container_info['name'], container_info.get('ostemplate', 'N/A'), container_info['status'], container_info['ip'])


        # Remove DB entries for VMs/containers no longer present in PVE
        current_db_vmids = {row['vmid'] for row in query_db('SELECT vmid FROM containers')}
        vanished_vmids_from_db = [db_vmid for db_vmid in current_db_vmids if db_vmid not in pve_container_vmids_set]
        for db_vmid in vanished_vmids_from_db:
             remove_container_from_db(db_vmid)
             app.logger.info(f"根据 PVE 列表移除数据库中不存在的容器和NAT规则记录: VMID {db_vmid}")

        cleanup_orphaned_nat_rules_in_db(pve_container_vmids_set)


    else:
        pve_container_error = True
        pve_container_error_message = f"PVE list 返回了未知数据格式或错误结构: {containers_data}"
        app.logger.error(pve_container_error_message)
        # Try loading from DB as a fallback again if parsing PVE output failed
        app.logger.warning("无法解析 PVE 列表，尝试从数据库加载容器列表。")
        for vmid, data in db_containers_dict.items():
             listed_containers.append({
                'vmid': vmid,
                'name': data.get('name', f'VMID {vmid} (DB)'),
                'status': data.get('status', 'Unknown (from DB)'),
                'ostemplate': data.get('ostemplate', 'N/A (from DB)'),
                'ip': data.get('ip', 'N/A (DB info)')
            })


    # --- List OS Templates ---
    # Use /nodes/{node}/storage/{storage}/content with type vztmpl
    success_tmpl, templates_data = run_pvesh_command(['ls', f'/nodes/{PVE_NODE}/storage/{PVE_STORAGE}/content', '--type', 'vztmpl'])

    if success_tmpl and isinstance(templates_data, list):
        for tmpl in templates_data:
             if not isinstance(tmpl, dict) or 'volid' not in tmpl:
                 app.logger.warning(f"Skipping invalid item in templates_data from PVE: {tmpl}")
                 continue
             # volid looks like storage_name:template/template_name.extension
             # We want the template_name part for display and creation
             volid = tmpl['volid']
             parts = volid.split('/')
             template_name_full = parts[-1] if parts else volid
             # Remove extension like .tar.gz
             template_name_display = template_name_full.split('.')[0] if '.' in template_name_full else template_name_full

             available_templates.append({'name': template_name_full, 'display_name': template_name_display}) # Use full name for creation command

    else:
        pve_template_error = True
        pve_template_error_message = templates_data if not success_tmpl else 'Invalid template data format from PVE.'
        app.logger.error(f"获取OS模板列表失败: {pve_template_error_message}")


    return render_template('index.html',
                           containers=listed_containers,
                           templates=available_templates,
                           pve_container_error=(pve_container_error, pve_container_error_message),
                           pve_template_error=(pve_template_error, pve_template_error_message))


# Note: Routes now use VMID as the identifier in the URL for consistency with PVE API
# However, the original request used container name in routes like /container/<name>/action
# Let's keep name in the URL but look up VMID internally.
# This requires VMID to be easily findable by name. The DB can serve this.

@app.route('/container/create', methods=['POST'])
def create_container():
    """Creates a new LXC container."""
    name = request.form.get('name')
    vmid_str = request.form.get('vmid')
    ostemplate = request.form.get('ostemplate')
    rootfs_size_str = request.form.get('rootfs_size', '8') # Default 8GB
    memory_mb_str = request.form.get('memory_mb', '512') # Default 512MB
    password = request.form.get('password', 'password') # Default password (INSECURE!) - require user input or better auth

    if not name or not vmid_str or not ostemplate:
        return jsonify({'status': 'error', 'message': '容器名称、VMID 和 OS 模板不能为空'}), 400

    try:
        vmid = int(vmid_str)
        if not (100 <= vmid <= 999999999): # PVE VMID range
             raise ValueError("VMID 必须是一个有效的Proxmox VE ID (通常100-999999999)。")
    except ValueError as e:
         return jsonify({'status': 'error', 'message': f'无效的 VMID: {e}'}), 400

    try:
         rootfs_size = int(rootfs_size_str)
         if not (1 <= rootfs_size <= 1000): # Arbitrary size limit
             raise ValueError("根文件系统大小必须在 1GB 到 1000GB 之间。")
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的根文件系统大小: {e}'}), 400

    try:
         memory_mb = int(memory_mb_str)
         if not (64 <= memory_mb <= 1000000): # Arbitrary memory limit (64MB to 1TB)
             raise ValueError("内存大小必须在 64MB 到 1000000MB (1TB) 之间。")
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的内存大小: {e}'}), 400

    # Basic validation: check if VMID exists in DB (might be stale, but good first check)
    db_exists_vmid = query_db('SELECT 1 FROM containers WHERE vmid = ?', [vmid], one=True)
    if db_exists_vmid:
        app.logger.warning(f"Attempted to create container with VMID {vmid} which already exists in DB.")
        return jsonify({'status': 'error', 'message': f'VMID "{vmid}" 在数据库中已存在记录。请尝试刷新列表或使用其他 VMID。'}), 409
    # Check if name exists in DB
    db_exists_name = query_db('SELECT 1 FROM containers WHERE name = ?', [name], one=True)
    if db_exists_name:
         app.logger.warning(f"Attempted to create container with name '{name}' which already exists in DB.")
         return jsonify({'status': 'error', 'message': f'名称 "{name}" 在数据库中已存在记录。请尝试刷新列表或使用其他名称。'}), 409


    # PVE create command for LXC
    # Need to specify storage for rootfs (--rootfs volume=<storage>:size=<size>G)
    # Need network config (--net0 name=eth0,bridge=vmbr0,ip=dhcp or static)
    # Need password (--password)
    # Need features like nesting if needed (--features nesting=1)
    # Minimal required: vmid, ostemplate, rootfs, memory, password, hostname, net0
    pve_create_command_args = [
        'create', f'/nodes/{PVE_NODE}/lxc', str(vmid),
        '--ostemplate', ostemplate,
        '--hostname', name,
        '--password', password, # **SECURITY WARNING: Hardcoded password or simple form input is INSECURE**
        '--rootfs', f'{PVE_STORAGE}:{rootfs_size}G',
        '--memory', str(memory_mb),
        '--cores', '1', # Default 1 core
        '--net0', 'name=eth0,bridge=vmbr0,ip=dhcp', # Default network config, using DHCP on vmbr0
        # Add --features nesting=1 if needed for docker inside lxc
    ]

    success, output = run_pvesh_command(pve_create_command_args, parse_json=False, timeout=180) # Creation can take time

    if success:
        # Container is created but likely stopped. Sync initial info.
        # Getting live info immediately after creation might not show everything (like IP)
        # Let's sync basic info based on the creation parameters and a placeholder status
        # A subsequent sync from `ls` will update the status.
        sync_container_to_db(vmid, name, ostemplate, 'stopped', 'N/A') # Initial sync

        return jsonify({'status': 'success', 'message': f'容器 {name} (VMID {vmid}) 创建操作已提交。请手动启动它并刷新列表以查看状态。'}), 200
    else:
        app.logger.error(f"Failed to create container {name} (VMID {vmid}): {output}")
        # Check if error indicates VMID/name conflict on PVE side
        if 'VMID is already used' in output or 'hostname already exists' in output:
             return jsonify({'status': 'error', 'message': f'创建容器 {name} (VMID {vmid}) 失败: VMID 或名称已存在于 PVE 中。{output}'}), 409

        return jsonify({'status': 'error', 'message': f'创建容器 {name} (VMID {vmid}) 失败: {output}'}), 500


@app.route('/container/<name>/action', methods=['POST'])
def container_action(name):
    """Performs start, stop, restart, or delete action on a container by name."""
    action = request.form.get('action')
    if not action:
         return jsonify({'status': 'error', 'message': '操作类型不能为空'}), 400

    success_vmid, vmid_info = get_vmid_from_name(name)
    if not success_vmid:
         return jsonify({'status': 'error', 'message': vmid_info}), 404
    vmid = vmid_info

    # PVE LXC actions via pvesh create /nodes/{node}/lxc/{vmid}/status/{action} or pvesh delete
    commands = {
        'start': ['create', f'/nodes/{PVE_NODE}/lxc/{vmid}/status/start'],
        'stop': ['create', f'/nodes/{PVE_NODE}/lxc/{vmid}/status/stop'],
        'restart': ['create', f'/nodes/{PVE_NODE}/lxc/{vmid}/status/reboot'], # PVE uses reboot for LXC restart
    }

    if action == 'delete':
        app.logger.info(f"Attempting to delete container {name} (VMID {vmid}) and its associated NAT rules.")

        success_db_rules, rules = get_nat_rules_for_container(vmid)
        if not success_db_rules:
             app.logger.error(f"Failed to fetch NAT rules for VMID {vmid} before deletion: {rules}")
             return jsonify({'status': 'error', 'message': f'删除容器前从数据库获取NAT规则失败: {rules}'}), 500

        failed_rule_deletions = []
        warning_rule_deletions = []
        if rules:
            app.logger.info(f"Found {len(rules)} associated NAT rules in DB for VMID {vmid}. Attempting iptables delete...")
            for rule in rules:
                if not all(key in rule for key in ['id', 'host_port', 'container_port', 'protocol', 'ip_at_creation']):
                     app.logger.error(f"Incomplete NAT rule details in DB for deletion, skipping iptables delete for rule: {rule}")
                     failed_rule_deletions.append(f"Rule ID {rule.get('id', 'N/A')} (数据库记录不完整)")
                     continue

                success_iptables_delete, iptables_message, is_bad_rule = perform_iptables_delete_for_rule(rule)

                if not success_iptables_delete:
                    if is_bad_rule:
                         warning_rule_deletions.append(iptables_message)
                         app.logger.warning(f"IPTables delete failed with 'Bad rule/Not Found' for rule ID {rule.get('id', 'N/A')}: {iptables_message}. Proceeding with DB delete.")
                         # Even if iptables delete failed because the rule wasn't found, we should remove the DB record
                         db_success, db_msg = remove_nat_rule_from_db(rule['id'])
                         if not db_success:
                              app.logger.error(f"IPTables rule deletion reported issue for ID {rule['id']}, but failed to remove record from DB: {db_msg}")
                    else:
                         failed_rule_deletions.append(iptables_message)
                         app.logger.error(f"IPTables delete failed (not Bad rule/Not Found) for rule ID {rule.get('id', 'N/A')}: {iptables_message}. Aborting container delete attempt for this rule.")

                else:
                    # iptables delete successful, now remove from DB
                    db_success, db_msg = remove_nat_rule_from_db(rule['id'])
                    if not db_success:
                        app.logger.error(f"IPTables rule deleted for ID {rule['id']}, but failed to remove record from DB: {db_msg}")

        if failed_rule_deletions:
            error_message = f"删除容器 {name} (VMID {vmid}) 前，未能移除所有关联的 NAT 规则 ({len(failed_rule_deletions)}/{len(rules) if rules else 0} 条 iptables 删除失败)。请手动检查 iptables。<br>失败详情: " + "; ".join(failed_rule_deletions)
            if warning_rule_deletions:
                 error_message += "<br>跳过的规则 (iptables 未找到): " + "; ".join(warning_rule_deletions)
            app.logger.error(error_message)
            return jsonify({'status': 'error', 'message': error_message}), 500

        app.logger.info(f"All {len(rules) if rules else 0} associated NAT rules for VMID {vmid} successfully handled for iptables delete (or none existed). Proceeding with PVE container deletion.")
        success_pve_delete, pve_output = run_pvesh_command(['delete', f'/nodes/{PVE_NODE}/lxc/{vmid}'], parse_json=False, timeout=120)

        if success_pve_delete:
            remove_container_from_db(vmid)
            message = f'容器 {name} (VMID {vmid}) 及其关联的 {len(rules) if rules else 0} 条 NAT 规则记录已成功删除。'
            if warning_rule_deletions:
                 message += "<br>注意: 部分 iptables 规则在删除时已不存在。"
            app.logger.info(message)
            return jsonify({'status': 'success', 'message': message}), 200
        else:
            error_message = f'删除容器 {name} (VMID {vmid}) 失败: {pve_output}'
            app.logger.error(error_message)
            # If PVE delete failed *after* successful iptables delete, the state is inconsistent. Log prominently.
            app.logger.critical(f"CRITICAL: PVE delete failed for VMID {vmid} AFTER IPTABLES RULES WERE DELETED.")
            return jsonify({'status': 'error', 'message': error_message}), 500

    if action not in commands:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400

    timeout_val = 60
    if action in ['stop', 'restart']: timeout_val = 120

    success, output = run_pvesh_command(commands[action], parse_json=False, timeout=timeout_val)

    if success:
        message = f'容器 {name} (VMID {vmid}) {action} 操作提交成功。'
        # Give PVE a moment to update status
        time.sleep(action in ['stop', 'restart', 'start'] and 3 or 1)

        # Attempt to get updated status from PVE list
        success_list_single, list_output = run_pvesh_command(['ls', f'/nodes/{PVE_NODE}/lxc', '--vmid', str(vmid)], timeout=10) # Filter list by vmid

        new_status_val = 'Unknown'
        db_ostemplate = 'N/A'
        db_ip = 'N/A'
        db_name = name # Keep current name if list lookup fails

        # Get existing DB info as fallback
        old_db_entry = query_db('SELECT name, ostemplate, status, ip FROM containers WHERE vmid = ?', [vmid], one=True)
        if old_db_entry:
             db_name = old_db_entry.get('name', name)
             db_ostemplate = old_db_entry.get('ostemplate', 'N/A')
             new_status_val = old_db_entry.get('status', 'Unknown')
             db_ip = old_db_entry.get('ip', 'N/A')


        if success_list_single and isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
            container_data = list_output[0]
            new_status_val = container_data.get('status', new_status_val)
            db_ip = container_data.get('ip', db_ip) # Update IP if running and available
            # ls output doesn't reliably have ostemplate or full config details
            message = f'容器 {name} (VMID {vmid}) {action} 操作成功，新状态: {new_status_val}。'
        else:
             # If PVE list failed, predict status based on action
             if action == 'start': new_status_val = 'running' # PVE status is lowercase
             elif action == 'stop': new_status_val = 'stopped'
             elif action == 'restart': new_status_val = 'running' # PVE will set to running if reboot succeeds
             message = f'容器 {name} (VMID {vmid}) {action} 操作提交成功，但无法获取最新状态（PVE列表或状态未立即更新）。'
             app.logger.warning(f"Failed to get updated status/IP for VMID {vmid} after {action}. PVE list output: {list_output}")

        # Sync updated status and IP to DB. Keep existing name/ostemplate if not updated via a more detailed sync.
        sync_container_to_db(vmid, db_name, db_ostemplate, new_status_val, db_ip)


        return jsonify({'status': 'success', 'message': message}), 200
    else:
        app.logger.error(f"PVE action '{action}' failed for {name} (VMID {vmid}): {output}")
        return jsonify({'status': 'error', 'message': f'容器 {name} (VMID {vmid}) {action} 操作失败: {output}'}), 500


@app.route('/container/<name>/exec', methods=['POST'])
def exec_command(name):
    """Executes a command inside a container using pct exec."""
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    success_vmid, vmid_info = get_vmid_from_name(name)
    if not success_vmid:
         return jsonify({'status': 'error', 'message': vmid_info}), 404
    vmid = vmid_info

    try:
        command_parts = shlex.split(command_to_exec)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的命令格式: {e}'}), 400

    if not command_parts:
         return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    # pct exec requires VMID and then the command
    pct_command_args = [str(vmid), 'exec', '--'] + command_parts

    success, output = run_pct_command(pct_command_args, parse_json=False, timeout=120)

    if success:
        return jsonify({'status': 'success', 'output': output}), 200
    else:
        # Output often contains the error message from the command itself
        return jsonify({'status': 'error', 'output': output, 'message': f'命令执行失败: {output}'}), 500


@app.route('/container/<name>/info')
def container_info(name):
    """Gets detailed information about a container by name."""
    success_vmid, vmid_info = get_vmid_from_name(name)
    if not success_vmid:
         return jsonify({'status': 'NotFound', 'message': vmid_info}), 404
    vmid = vmid_info

    info_output, error_message = _get_container_raw_info(vmid)

    if info_output is None:
        return jsonify({'status': 'NotFound', 'message': error_message}), 404
    else:
        return jsonify(info_output), 200


@app.route('/container/<name>/add_nat_rule', methods=['POST'])
def add_nat_rule(name):
    """Adds a NAT (port forwarding) rule for a container by name."""
    host_port = request.form.get('host_port')
    container_port = request.form.get('container_port')
    protocol = request.form.get('protocol')

    if not host_port or not container_port or not protocol:
         return jsonify({'status': 'error', 'message': '主机端口、容器端口和协议不能为空'}), 400
    try:
        host_port = int(host_port)
        container_port = int(container_port)
        if not (1 <= host_port <= 65535) or not (1 <= container_port <= 65535):
            raise ValueError("端口号必须在 1 到 65535 之间。")
    except ValueError as e:
         return jsonify({'status': 'error', 'message': f'端口号无效: {e}'}), 400

    if protocol.lower() not in ['tcp', 'udp']:
         return jsonify({'status': 'error', 'message': '协议必须是 tcp 或 udp'}), 400
    protocol = protocol.lower() # Ensure lowercase

    success_vmid, vmid_info = get_vmid_from_name(name)
    if not success_vmid:
         return jsonify({'status': 'NotFound', 'message': vmid_info}), 404
    vmid = vmid_info


    db_check_success, rule_exists = check_nat_rule_exists_in_db(vmid, host_port, protocol)
    if not db_check_success:
        app.logger.error(f"检查现有 NAT 规则记录失败: {rule_exists}")
        return jsonify({'status': 'error', 'message': f"检查现有 NAT 规则记录失败: {rule_exists}"}), 500
    if rule_exists:
        message = f'容器 {name} (VMID {vmid}) 的主机端口 {host_port}/{protocol} NAT 规则已存在记录，跳过添加。'
        app.logger.warning(message)
        # Should we check if the iptables rule exists? For now, assume DB record implies iptables rule exists.
        # A full check would involve listing iptables rules and parsing output, complex.
        return jsonify({'status': 'warning', 'message': message}), 200 # Use 200 as it's not an error, just skipped


    container_info_data, info_error_message = _get_container_raw_info(vmid)

    if container_info_data is None:
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} (VMID {vmid}) 信息以确定 IP: {info_error_message}'}), 500 # Use 500 as it's internal failure


    if container_info_data.get('status') != 'running':
         status_msg = container_info_data.get('status', 'Unknown')
         # Allow adding rules even if stopped, but warn? No, iptables needs a destination IP.
         # The IP lookup above would fail anyway if not running unless IP is static.
         # For simplicity based on original Incus logic, require running to get current IP.
         return jsonify({'status': 'error', 'message': f'容器 {name} (VMID {vmid}) 必须处于 Running 状态才能添加 NAT 规则 (当前状态: {status_msg})。'}), 400

    container_ip = container_info_data.get('ip')

    if not container_ip or container_ip == 'N/A' or 'Parse Failed' in container_ip or 'Exec Failed' in container_ip:
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} (VMID {vmid}) 的 IP 地址。请确保容器正在运行且已分配 IP (DHCP 或静态配置正确)，且 'pct exec' 可用。当前 IP: {container_ip}'}), 500

    rule_details = {
         'vmid': vmid,
         'host_port': host_port,
         'container_port': container_port,
         'protocol': protocol,
         'ip_at_creation': container_ip # Store the IP used for the iptables rule
    }

    success_iptables, output = perform_iptables_add(rule_details)


    if success_iptables:
        db_success, db_result = add_nat_rule_to_db(rule_details)

        message = f'已成功为容器 {name} (VMID {vmid}) 添加 NAT 规则: 主机端口 {host_port}/{protocol} 转发到容器 IP {container_ip} 端口 {container_port}。'

        if not db_success:
             message += f" 但记录规则到数据库失败: {db_result}"
             app.logger.error(f"Failed to record NAT rule for VMID {vmid} in DB after successful iptables: {db_result}")
             return jsonify({'status': 'warning', 'message': message}), 200 # Warn user but indicate iptables rule is added

        return jsonify({'status': 'success', 'message': message, 'rule_id': db_result}), 200

    else:
        message = f'添加 NAT 规则失败: {output}'
        app.logger.error(f"iptables command failed for VMID {vmid}: {output}")
        return jsonify({'status': 'error', 'message': message}), 500

@app.route('/container/<name>/nat_rules', methods=['GET'])
def list_nat_rules(name):
    """Lists NAT rules for a container by name."""
    success_vmid, vmid_info = get_vmid_from_name(name)
    if not success_vmid:
         return jsonify({'status': 'NotFound', 'message': vmid_info}), 404
    vmid = vmid_info

    success, rules = get_nat_rules_for_container(vmid)
    if success:
        # Optionally add container name to each rule dict for easier template rendering
        rules_with_name = [dict(rule, container_name=name) for rule in rules]
        return jsonify({'status': 'success', 'rules': rules_with_name}), 200
    else:
        return jsonify({'status': 'error', 'message': rules}), 500 # 'rules' contains error message on failure

@app.route('/container/nat_rule/<int:rule_id>', methods=['DELETE'])
def delete_nat_rule(rule_id):
    """Deletes a specific NAT rule by its database ID."""
    app.logger.info(f"Attempting to delete NAT rule ID {rule_id}.")
    success_db, rule = get_nat_rule_by_id(rule_id)

    if not success_db:
         app.logger.error(f"Error fetching rule ID {rule_id} from DB for deletion: {rule}")
         return jsonify({'status': 'error', 'message': f'删除NAT规则前从数据库获取规则失败: {rule}'}), 500

    if not rule:
        app.logger.warning(f"NAT rule ID {rule_id} not found in DB for deletion.")
        return jsonify({'status': 'warning', 'message': f'数据库中找不到ID为 {rule_id} 的NAT规则记录，可能已被手动删除。跳过 iptables 删除和数据库删除。'}), 200

    # rule dictionary should contain vmid, host_port, container_port, protocol, ip_at_creation
    # Check required keys just in case DB schema is wrong or entry is corrupt
    required_keys = ['vmid', 'host_port', 'container_port', 'protocol', 'ip_at_creation']
    if not all(key in rule for key in required_keys):
         app.logger.error(f"NAT rule ID {rule_id} in DB has missing required keys for deletion: {rule}")
         return jsonify({'status': 'error', 'message': f'数据库中ID为 {rule_id} 的规则记录不完整，无法删除。请手动检查数据库。'}), 500


    success_iptables, iptables_message, is_bad_rule = perform_iptables_delete_for_rule(rule)

    if success_iptables or is_bad_rule:
        # Remove from DB regardless of whether iptables delete succeeded or found the rule (is_bad_rule)
        db_success, db_message = remove_nat_rule_from_db(rule_id)

        message = f'已成功删除ID为 {rule_id} 的NAT规则记录。'
        if is_bad_rule:
             message = f'数据库记录已删除 (ID {rule_id})。注意：该规则在 iptables 中未找到或已不存在。'

        if not db_success:
             message += f" 但从数据库移除记录失败: {db_message}"
             app.logger.error(f"IPTables rule deletion succeeded or was 'Bad rule/Not Found' for ID {rule['id']}, but failed to remove record from DB: {db_message}")
             return jsonify({'status': 'warning', 'message': message}), 200 # Warning but indicates DB issue after iptables attempt

        return jsonify({'status': 'success', 'message': message}), 200
    else:
        # If iptables delete failed for a reason *other* than rule not found, don't remove from DB
        message = f'删除ID为 {rule_id} 的NAT规则失败: {iptables_message}'
        app.logger.error(f"iptables delete command failed for rule ID {rule_id}: {iptables_message}")
        return jsonify({'status': 'error', 'message': message}), 500


def check_pve_tools():
    """Checks if pvesh and pct commands are available."""
    errors = []
    try:
        subprocess.run(['pvesh', 'help'], check=True, capture_output=True, text=True, timeout=10)
        print("pvesh 命令检查通过。")
    except FileNotFoundError:
         errors.append("'pvesh' 命令未找到。请确保 Proxmox VE 已正确安装并配置了 PATH。")
    except subprocess.CalledProcessError as e:
         errors.append(f"执行 'pvesh help' 失败 (退出码 {e.returncode}): {e.stderr.strip()}. 请检查 PVE 安装或权限问题。")
    except subprocess.TimeoutExpired:
         errors.append("执行 'pvesh help' 超时。")
    except Exception as e:
         errors.append(f"启动时 pvesh 检查发生异常: {e}")

    try:
        subprocess.run(['pct', 'help'], check=True, capture_output=True, text=True, timeout=10)
        print("pct 命令检查通过。")
    except FileNotFoundError:
         errors.append("'pct' 命令未找到。请确保 Proxmox VE 已正确安装并配置了 PATH。")
    except subprocess.CalledProcessError as e:
         errors.append(f"执行 'pct help' 失败 (退出码 {e.returncode}): {e.stderr.strip()}. 请检查 PVE 安装或权限问题。")
    except subprocess.TimeoutExpired:
         errors.append("执行 'pct help' 超时。")
    except Exception as e:
         errors.append(f"启动时 pct 检查发生异常: {e}")

    return errors


def check_iptables():
    """Checks if iptables command is available and warns about permissions."""
    errors = []
    try:
        subprocess.run(['iptables', '--version'], check=True, capture_output=True, text=True, timeout=5)
        print("iptables 命令检查通过。")
        if os.geteuid() != 0:
            print("警告: 当前用户不是 root。执行 iptables 命令需要 root 权限，否则NAT功能可能无法使用。")
            print("请考虑使用 'sudo python app.py' 运行此应用 (注意安全性风险)。")
        else:
            print("当前用户是 root。可以执行 iptables 命令。")
    except FileNotFoundError:
         errors.append("'iptables' 命令未找到。NAT 功能可能无法使用。")
    except subprocess.CalledProcessError as e:
         errors.append(f"执行 'iptables --version' 失败 (退出码 {e.returncode}): {e.stderr.strip()}. iptables 命令可能存在问题或权限不足。")
         if os.geteuid() != 0:
             print("警告: 当前用户不是 root。请确认是否有权限执行 iptables.")
    except subprocess.TimeoutExpired:
         errors.append("执行 'iptables --version' 超时。")
    except Exception as e:
         errors.append(f"启动时 iptables 检查发生异常: {e}")

    return errors


def main():
    """Main function to perform checks and run the app."""
    print(f"使用 PVE 节点: {PVE_NODE}")
    print(f"使用 PVE 存储 (模板): {PVE_STORAGE}")

    if not os.path.exists(DATABASE_NAME):
        print(f"错误：数据库文件 '{DATABASE_NAME}' 未找到。")
        print("请先运行配套的 'init_db.py' 脚本来初始化数据库结构。")
        sys.exit(1)

    conn = None
    db_errors = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check containers table schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            db_errors.append(f"错误：数据库表 'containers' 在 '{DATABASE_NAME}' 中未找到。")
        else:
            cursor.execute("PRAGMA table_info(containers);")
            containers_columns_info = cursor.fetchall()
            containers_column_names = {col[1] for col in containers_columns_info}
            required_container_columns = {'vmid', 'name', 'status', 'ostemplate', 'ip', 'last_synced'}
            missing_container_columns = required_container_columns - containers_column_names
            if missing_container_columns:
                db_errors.append(f"错误：数据库表 'containers' 缺少必需的列: {', '.join(missing_container_columns)}. 请更新 init_db.py。")

            # Check if vmid is primary key (heuristic)
            vmid_pk = any(col[5] for col in containers_columns_info if col[1] == 'vmid')
            if not vmid_pk:
                 db_errors.append("警告：数据库表 'containers' 的 'vmid' 列可能不是 PRIMARY KEY。请检查 init_db.py。")

            # Check if name is unique
            cursor.execute("PRAGMA index_list(containers);")
            indexes = cursor.fetchall()
            has_unique_name = False
            for idx in indexes:
                if idx[2] == 1: # unique flag
                    cursor.execute(f"PRAGMA index_info('{idx[1]}');")
                    idx_cols = [col[2] for col in cursor.fetchall()]
                    if len(idx_cols) == 1 and idx_cols[0] == 'name':
                         has_unique_name = True
                         break
            if not has_unique_name:
                 db_errors.append("警告：数据库表 'containers' 的 'name' 列可能没有 UNIQUE 约束。这可能导致同步问题。建议更新 init_db.py。")


        # Check nat_rules table schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
             db_errors.append(f"错误：数据库表 'nat_rules' 在 '{DATABASE_NAME}' 中未找到。")
        else:
            cursor.execute("PRAGMA table_info(nat_rules);")
            nat_columns_info = cursor.fetchall()
            nat_column_names = {col[1] for col in nat_columns_info}
            required_nat_columns = {'id', 'vmid', 'host_port', 'container_port', 'protocol', 'ip_at_creation', 'created_at'}
            missing_nat_columns = required_nat_columns - nat_column_names
            if missing_nat_columns:
                 db_errors.append(f"错误：数据库表 'nat_rules' 缺少必需的列: {', '.join(missing_nat_columns)}. 请更新 init_db.py。")

            # Check unique composite index on (vmid, host_port, protocol)
            cursor.execute("PRAGMA index_list(nat_rules);")
            indexes = cursor.fetchall()
            unique_composite_index_exists = False
            expected_unique_cols = sorted(['vmid', 'host_port', 'protocol'])
            for index_info in indexes:
                if index_info[2] == 1: # unique flag
                    index_name = index_info[1]
                    cursor.execute(f"PRAGMA index_info('{index_name}');")
                    idx_cols = sorted([col[2] for col in cursor.fetchall()])
                    if idx_cols == expected_unique_cols:
                         unique_composite_index_exists = True
                         break
            if not unique_composite_index_exists:
                 db_errors.append("警告：数据库表 'nat_rules' 可能缺少 UNIQUE (vmid, host_port, protocol) 约束。这可能导致重复规则记录。建议更新 init_db.py。")


    except sqlite3.Error as e:
        db_errors.append(f"启动时数据库检查发生异常: {e}")
    finally:
        if conn:
            conn.close()

    if db_errors:
         print("\n--- 数据库检查错误/警告 ---")
         for err in db_errors:
              print(err)
         print("-------------------------\n")
         if any("错误" in err for err in db_errors):
             print("发现致命数据库错误，无法启动。请修正 init_db.py 并重新运行。")
             sys.exit(1)


    pve_tool_errors = check_pve_tools()
    iptables_errors = check_iptables()

    if pve_tool_errors or iptables_errors:
         print("\n--- 工具命令检查错误/警告 ---")
         for err in pve_tool_errors + iptables_errors:
              print(err)
         print("---------------------------\n")
         if pve_tool_errors:
             print("发现致命命令错误，无法启动。请确认 pvesh 和 pct 可执行。")
             sys.exit(1)


    print("启动 Flask Web 服务器...")
    # Setting threaded=True can help with blocking subprocess calls
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)

if __name__ == '__main__':
    main()
