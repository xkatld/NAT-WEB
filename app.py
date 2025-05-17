import os
import subprocess
import shlex
import re # 引入正则表达式库
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Optional, ValidationError

# 硬编码公网网卡名称 - 注意：在实际部署中可能需要根据环境配置
PUBLIC_INTERFACE = os.environ.get('PUBLIC_INTERFACE', 'enp7s0') # 允许从环境变量配置

app = Flask(__name__)
# 生产环境中务必修改此密钥，用于保护会话信息
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_fallback')

def execute_iptables_command(cmd):
    """
    安全地执行 iptables 命令。
    使用列表形式调用 subprocess.run，避免 shell 注入。
    包含基础的参数检查。
    """
    # 基础安全检查，防止明显注入字符
    # 注意：这不是完全安全的输入过滤，生产环境需要更完善的验证
    # 这些字符在普通IP、端口、协议、接口名中不常见
    forbidden_chars = ['&', '|', ';', '`', '$', '>', '<', '(', ')', '{', '}', '\\', '*']
    for arg in cmd:
         arg_str = str(arg) # 确保参数是字符串以便检查
         if any(c in arg_str for c in forbidden_chars):
             print(f"SECURITY ALERT: Potential command injection attempt detected in argument: {arg_str}")
             return False, f"错误：命令参数中包含无效字符: {arg_str}"

    print(f"正在执行命令: {' '.join(shlex.quote(str(arg)) for arg in cmd)}") # 打印引用后的命令方便调试

    try:
        # 使用 root 权限执行 iptables
        # 生产环境应采用更安全的方式，如配置 sudoers 允许非特权用户执行特定 iptables 命令
        # timeout 避免命令长时间挂起
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
        # iptables 成功时通常没有 stdout，但可能有 stderr 警告
        if result.stderr:
            print("Stderr (可能有警告):", result.stderr.strip())
        print("命令执行成功。")
        return True, result.stderr.strip() if result.stderr else "成功"
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败，退出码 {e.returncode}")
        print("Stderr:", e.stderr.strip())
        return False, f"命令执行失败 (退出码 {e.returncode}): {e.stderr.strip()}"
    except FileNotFoundError:
         print("未找到 iptables 命令。请确保已安装 iptables 且在 PATH 中。")
         return False, "未找到 iptables 命令"
    except Exception as e:
         print(f"发生未知错误: {e}")
         return False, f"发生未知错误: {e}"

def list_nat_rules(table, chain):
    """列出指定 iptables 表和链的规则，带行号，更宽松地解析"""
    # 使用 -v -n --line-numbers 参数获取详细信息和行号
    cmd = ['iptables', '-t', table, '-L', chain, '-v', '-n', '--line-numbers']
    print(f"正在列出规则: {' '.join(cmd)}")

    try:
        # 需要 root 权限读取规则
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
        output_lines = result.stdout.splitlines()

        rules = []
        # 解析 iptables -L --line-numbers -v -n 的输出
        # 输出格式大致为:
        # Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
        # num   pkts bytes target     prot opt in     out     source               destination
        # 1        0     0 DNAT       tcp  --  enp7s0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:192.168.1.100:80
        # 2        0     0 MASQUERADE all  --  *      enp7s0  192.168.1.0/24       0.0.0.0/0

        # 查找表头行，确定列的起始位置（这个可能随版本变化，简单拆分更通用）
        header_found = False
        header_parts = []
        for line in output_lines:
            line = line.strip()
            if line.startswith('Chain'):
                # 提取链的策略和计数 (可选)
                policy_match = re.search(r'policy (\w+) (\d+) packets, (\d+) bytes', line)
                if policy_match:
                    chain_policy = policy_match.group(1)
                    # print(f"Chain {chain} policy: {chain_policy}") # 可以记录策略，当前未使用
                continue
            if line.startswith('num'): # 找到表头
                 header_found = True
                 # header_parts = line.split() # 实际解析时不完全依赖这个，只是标记开始
                 continue
            if not header_found or not line:
                 continue # 跳过头部信息、非规则行和空行

            # 尝试解析规则行 - 假设前10个字段是标准字段
            # num pkts bytes target prot opt in out source destination
            parts = line.split(maxsplit=9) # 最多分割9次，将第10个及以后的部分作为单个元素

            if len(parts) < 10 or not parts[0].isdigit():
                 # 如果分割后少于10个部分，或者第一个部分不是数字（行号），则跳过
                 continue

            try:
                 # 提取标准字段
                 line_num = int(parts[0])
                 pkts = parts[1]
                 bytes_val = parts[2]
                 target = parts[3]
                 prot = parts[4]
                 opt = parts[5]
                 in_if = parts[6]
                 out_if = parts[7]
                 source = parts[8]
                 destination = parts[9]

                 # 剩余部分是扩展匹配条件和动作参数
                 extra_info = " ".join(line.split()[10:]) if len(line.split()) > 10 else "" # 重新split获取所有部分以便join剩余的

                 rules.append({
                     'line_number': line_num,
                     'pkts': pkts,
                     'bytes': bytes_val,
                     'target': target,
                     'protocol': prot,
                     'opt': opt,
                     'in_interface': in_if,
                     'out_interface': out_if,
                     'source': source,
                     'destination': destination,
                     'extra_info': extra_info.strip(), # 保留原始扩展信息
                     # 可以尝试从 extra_info 提取 DNAT 特定字段用于美化显示，但保留 extra_info 作为原始参考
                     # 例如，提取 to:
                     'to_destination': None
                 })

                 # 尝试为 DNAT 规则解析出 to:destination (仅为方便显示，不用于删除逻辑)
                 if target == 'DNAT':
                      to_match = re.search(r'to:([\w\d\.:-]+)', extra_info)
                      if to_match:
                           rules[-1]['to_destination'] = to_match.group(1)
                      # 尝试提取 dpt: (也仅为显示)
                      dport_match = re.search(r'dpt:(\d+)', extra_info)
                      if dport_match:
                           # 将dpt添加到 extra_info 或单独字段，这里为了显示放入extra_info或结合to_dest显示
                           # 更好的做法可能是直接在extra_info中显示原始dpt:，并在UI中结合to_destination
                           pass # extra_info already contains dpt:

            except (ValueError, IndexError) as e:
                 print(f"Warning: Failed to parse iptables line '{line}': {e}")
                 # 继续解析下一行
                 continue

        return True, rules, "" # success, list of rules, empty error message

    except subprocess.CalledProcessError as e:
        error_msg = f"列出 iptables 规则失败: {e.stderr.strip()}"
        print(error_msg)
        return False, [], error_msg
    except FileNotFoundError:
         error_msg = "未找到 iptables 命令。"
         print(error_msg)
         return False, [], error_msg
    except Exception as e:
         error_msg = f"列出 iptables 规则时发生未知错误: {e}"
         print(error_msg)
         return False, [], error_msg

def check_masquerade_rule_exists(interface):
    """检查 nat 表 POSTROUTING 链是否存在指向指定接口的 MASQUERADE 规则"""
    cmd = ['iptables', '-t', 'nat', '-L', 'POSTROUTING', '-n'] # 使用 -n 避免 DNS 查找
    print(f"检查 MASQUERADE 规则: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace')
        # 查找包含 "-o <interface> -j MASQUERADE" 的行
        # 注意：这只是检查一个常见形式，MASQUERADE 规则可以更复杂
        pattern = re.compile(r'MASQUERADE\s+all\s+--\s+\*\s+' + re.escape(interface))
        for line in result.stdout.splitlines():
             if pattern.search(line):
                  print(f"找到匹配的 MASQUERADE 规则在接口 {interface}")
                  return True
        print(f"未找到匹配的 MASQUERADE 规则在接口 {interface}")
        return False
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        print(f"检查 MASQUERADE 规则时发生错误: {e}")
        # 如果检查失败，保守起见认为不存在或者无法确定
        return False


# 简化后的 DNAT 添加表单
class AddDnatRuleForm(FlaskForm):
    form_id = HiddenField('form_id', default='add_dnat') # 用于区分表单提交
    protocol = SelectField('协议', choices=[('tcp', 'TCP'), ('udp', 'UDP')], validators=[DataRequired('协议是必填项')])
    public_port = StringField('主机端口', validators=[DataRequired('主机端口是必填项')])
    internal_ip = StringField('内网 IP 地址', validators=[DataRequired('内网 IP 是必填项')])
    container_port = StringField('容器端口', validators=[DataRequired('容器端口是必填项')])
    submit = SubmitField('添加规则')

    def validate_public_port(self, field):
         try:
              port = int(field.data)
              if not 1 <= port <= 65535:
                   raise ValidationError('端口必须在 1 到 65535 之间。')
         except ValueError:
              raise ValidationError('端口必须是数字。')

    def validate_container_port(self, field):
         try:
              port = int(field.data)
              if not 1 <= port <= 65535:
                   raise ValidationError('端口必须在 1 到 65535 之间。')
         except ValueError:
              raise ValidationError('端口必须是数字。')

    def validate_internal_ip(self, field):
         # Basic IPv4 format check (not a full validation like existence or correctness)
         parts = field.data.split('.')
         if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
              raise ValidationError('内网 IP 格式无效 (例如: 192.168.1.100)。')

# MASQUERADE 管理表单
class MasqueradeForm(FlaskForm):
    form_id = HiddenField('form_id', default='manage_masq') # 用于区分表单提交
    submit_add = SubmitField('添加/确保 MASQUERADE')
    submit_remove = SubmitField('移除 MASQUERADE (第一个)') # 添加移除按钮

@app.route('/', methods=['GET', 'POST'])
def index():
    dnat_form = AddDnatRuleForm() # 无论 GET 还是 POST 都先创建表单实例
    masq_form = MasqueradeForm()

    # 处理 POST 请求
    if request.method == 'POST':
        form_id = request.form.get('form_id')

        if form_id == 'add_dnat' and dnat_form.validate_on_submit():
            # 构建 DNAT iptables 命令
            cmd = [
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', PUBLIC_INTERFACE, # 指定入站接口
                '-p', dnat_form.protocol.data,
                '--dport', dnat_form.public_port.data,
                '-j', 'DNAT',
                '--to-destination', f"{dnat_form.internal_ip.data}:{dnat_form.container_port.data}"
            ]
            ok, msg = execute_iptables_command(cmd)

            if ok:
                flash('端口转发规则添加成功。', 'success')
            else:
                flash(f'添加规则失败: {msg}', 'danger')

        elif form_id == 'manage_masq':
             # MASQUERADE 表单提交
             if masq_form.validate_on_submit(): # 验证 CSRF token
                 if masq_form.submit_add.data: # 点击的是添加/确保按钮
                     # 简单的添加逻辑，可能会添加重复规则
                     cmd_add_masq = [
                         'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                         '-o', PUBLIC_INTERFACE, # 在出站接口应用
                         '-j', 'MASQUERADE'
                     ]
                     ok_add, msg_add = execute_iptables_command(cmd_add_masq)
                     if ok_add:
                         flash('MASQUERADE 规则添加成功。', 'success')
                     else:
                         flash(f'添加 MASQUERADE 规则失败: {msg_add}', 'danger')
                 elif masq_form.submit_remove.data: # 点击的是移除按钮
                     # 尝试移除第一条匹配的 MASQUERADE 规则
                     # 找到第一条匹配规则的行号并删除
                     ok_list, postrouting_rules, _ = list_nat_rules('nat', 'POSTROUTING')
                     removed = False
                     if ok_list:
                          for rule in postrouting_rules:
                              # 简单检查目标和出站接口
                              if rule['target'] == 'MASQUERADE' and rule['out_interface'] == PUBLIC_INTERFACE:
                                   cmd_remove_masq = ['iptables', '-t', 'nat', '-D', 'POSTROUTING', str(rule['line_number'])]
                                   ok_remove, msg_remove = execute_iptables_command(cmd_remove_masq)
                                   if ok_remove:
                                        flash(f'第一条匹配的 MASQUERADE 规则 (行号 {rule["line_number"]}) 移除成功。', 'success')
                                   else:
                                        flash(f'移除 MASQUERADE 规则失败 (行号 {rule["line_number"]}): {msg_remove}', 'danger')
                                   removed = True
                                   break # 只移除第一条
                          if not removed:
                               flash('未找到匹配的 MASQUERADE 规则可移除。', 'info')
                     else:
                          flash('无法列出 POSTROUTING 规则，无法移除 MASQUERADE。', 'danger')

             else:
                  # MASQUERADE 表单验证失败（通常是 CSRF）
                  flash('MASQUERADE 操作失败，请刷新页面重试。', 'danger')


        elif 'delete_rule_submit' in request.form: # 通过删除按钮的 name 判断
             # 使用 request.form.get('line_number') 获取值
             line_number_str = request.form.get('line_number')
             if line_number_str:
                 try:
                      line_number = int(line_number_str)
                      # 使用行号删除规则 (注意：行号可能因其他规则变动而变化)
                      cmd = ['iptables', '-t', 'nat', '-D', 'PREROUTING', str(line_number)] # 行号作为字符串传递
                      ok, msg = execute_iptables_command(cmd)
                      if ok:
                          flash(f'规则 (行号 {line_number}) 删除成功。', 'success')
                      else:
                          # 失败时，msg 里包含了 stderr 输出
                          flash(f'删除规则 (行号 {line_number}) 失败: {msg}', 'danger')
                 except ValueError:
                      flash('无效的规则行号。', 'danger')
                 except Exception as e:
                      flash(f'删除规则时发生意外错误: {e}', 'danger')
             else:
                  flash('未能获取规则行号进行删除。', 'danger')

        else:
             # 如果提交的 POST 没有 form_id 或 delete_rule_submit，则为未知请求
             flash('未知操作请求。', 'warning')

        # 重定向到首页以防止刷新重复提交，并触发 GET 请求重新加载规则列表和状态
        return redirect(url_for('index'))

    # 处理 GET 请求
    # 在 GET 请求时，list_nat_rules 会获取当前的规则列表
    ok, prerouting_rules, error_msg = list_nat_rules('nat', 'PREROUTING')
    if not ok:
         flash(f"无法加载当前的 NAT PREROUTING 规则: {error_msg}", 'danger')
         # 仍尝试渲染页面，规则列表可能为空 []

    masquerade_exists = check_masquerade_rule_exists(PUBLIC_INTERFACE)

    return render_template('index.html',
                           dnat_form=dnat_form,
                           masq_form=masq_form,
                           rules=prerouting_rules, # PREROUTING 规则
                           public_interface=PUBLIC_INTERFACE,
                           masquerade_exists=masquerade_exists) # MASQUERADE 状态

@app.route('/clear_all_prerouting', methods=['POST'])
def clear_all_prerouting():
    """清空 NAT PREROUTING 链的所有规则"""
    # 验证 CSRF token
    form = FlaskForm(request.form) # 使用一个通用表单只为验证 CSRF
    if not form.validate_on_submit():
         flash('安全验证失败，无法清空规则。', 'danger')
         return redirect(url_for('index'))

    cmd = ['iptables', '-t', 'nat', '-F', 'PREROUTING']
    ok, msg = execute_iptables_command(cmd)
    if ok:
        flash('成功清空 NAT PREROUTING 链的所有规则。', 'success')
    else:
        flash(f'清空 NAT PREROUTING 链失败: {msg}', 'danger')
    return redirect(url_for('index'))


# 启动时的初始化，只打印警告信息，不执行 iptables 操作
if __name__ == '__main__':
    print("\n!!! 安全警告 !!!")
    print("此应用管理系统防火墙规则，可能需要 root 权限才能执行 iptables 命令。")
    print("在生产环境中以 root 运行 Web 服务器是 非 常 危 险 的。")
    print(f"硬编码的公网网卡为: {PUBLIC_INTERFACE} (可通过环境变量 PUBLIC_INTERFACE 覆盖)")
    print("当前管理的规则不持久化，主机重启后会丢失，需要额外的系统服务来保存和恢复规则。")
    print("!!! 安全警告 !!!\n")

    # app.run() 函数会自己处理请求和应用上下文
    # debug=True 仅用于开发环境，生产环境请禁用
    app.run(host='0.0.0.0', port=5000, debug=True) # 开发阶段开启 debug 方便排错
