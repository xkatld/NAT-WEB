import os
import subprocess
import shlex
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional, ValidationError

PUBLIC_INTERFACE = 'enp7s0' # 硬编码公网网卡名称

app = Flask(__name__)
# 生产环境中务必修改此密钥，用于保护会话信息
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_fallback')

def execute_iptables_command(cmd):
    safe_cmd = []
    for arg in cmd:
         # 基础安全检查，防止明显注入字符
         if any(c in str(arg) for c in ['&', '|', ';', '`', '$', '>', '<', '(', ')', '{', '}', '\\', '*']):
             print(f"SECURITY ALERT: Potential command injection attempt detected in argument: {arg}")
             return False, f"错误：命令参数中包含无效字符: {arg}"
         safe_cmd.append(str(arg)) # 确保所有参数都是字符串

    cmd_str = ' '.join(shlex.quote(arg) for arg in safe_cmd)
    print(f"正在执行命令: {cmd_str}")

    try:
        # 使用 root 权限执行 iptables
        # 生产环境应采用更安全的方式，如配置 sudoers 允许非特权用户执行特定 iptables 命令
        result = subprocess.run(safe_cmd, check=True, capture_output=True, text=True, timeout=10)
        print("命令执行成功。")
        # print("Stdout:", result.stdout) # 可选的详细日志
        # print("Stderr:", result.stderr) # 可选的详细日志
        return True, "成功"
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败，退出码 {e.returncode}")
        # print("Stdout:", e.stdout) # 可选的详细日志
        # print("Stderr:", e.stderr) # 可选的详细日志
        return False, f"命令执行失败: {e.stderr.strip()}"
    except FileNotFoundError:
         print("未找到 iptables 命令。")
         return False, "未找到 iptables 命令"
    except Exception as e:
         print(f"发生未知错误: {e}")
         return False, f"发生未知错误: {e}"

def list_nat_prerouting_rules():
    """列出当前 iptables nat 表 PREROUTING 链的规则，带行号"""
    cmd = ['iptables', '-t', 'nat', '-L', 'PREROUTING', '-v', '-n', '--line-numbers']
    print(f"正在执行命令: {' '.join(cmd)}")
    try:
        # 同样需要 root 权限读取规则
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
        output_lines = result.stdout.splitlines()

        rules = []
        # 跳过头部信息，查找规则行
        # 规则行通常以行号开头，后跟 target, prot, opt, in, out, source, destination 等
        # 例如: 1     0     0 DNAT     tcp  --  any    any    anywhere             anywhere             tcp dpt:80 to:192.168.1.100:80
        rule_line_start = False
        for line in output_lines:
            line = line.strip()
            if not line or line.startswith('Chain') or line.startswith('pkts'):
                continue # 跳过空行、Chain行、表头行

            # 尝试解析规则行
            parts = line.split()
            if len(parts) < 10: # 简单的长度检查，规则行通常更长
                 continue

            try:
                 line_num = int(parts[0])
                 # 简单的解析，只提取关键信息用于显示
                 rule_data = {
                      'line_number': line_num,
                      'pkts': parts[1],
                      'bytes': parts[2],
                      'target': parts[3],
                      'prot': parts[4],
                      'in': parts[5],
                      'out': parts[6],
                      'source': parts[7],
                      'destination': parts[8],
                      'full_rule_str': line # 保存原始行用于调试或更详细显示
                 }

                 # 解析 --dport, --to-destination 等扩展匹配
                 extra_info = " ".join(parts[9:])
                 if 'dpt:' in extra_info:
                      dpt_str = extra_info.split('dpt:')[1].split(' ')[0]
                      rule_data['dport'] = dpt_str.split(':')[0] # Handle dpt:port/protocol format
                 if 'to:' in extra_info:
                      to_dest_str = extra_info.split('to:')[1].split(' ')[0]
                      rule_data['to_destination'] = to_dest_str

                 # 只列出我们关注的 DNAT 规则，并且入站接口是我们硬编码的公网接口
                 if rule_data['target'] == 'DNAT' and rule_data.get('in') in [PUBLIC_INTERFACE, 'any'] and rule_data.get('prot') in ['tcp', 'udp']: # Check protocol
                      # 我们只解析并展示我们创建规则时会涉及的字段
                      rules.append({
                           'line_number': rule_data['line_number'],
                           'protocol': rule_data.get('prot', 'any'),
                           'in_interface': rule_data.get('in', 'any'),
                           'dport': rule_data.get('dport', '-'),
                           'to_destination': rule_data.get('to_destination', '-'),
                           'description': '-' # 无法从iptables规则中获取描述
                      })


            except (ValueError, IndexError) as e:
                 print(f"Warning: Failed to parse iptables line '{line}': {e}")
                 continue # Skip lines that don't match expected format

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


# 简化后的 DNAT 添加表单
class AddDnatRuleForm(FlaskForm):
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
         # Basic IP format check (not a full validation)
         parts = field.data.split('.')
         if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
              raise ValidationError('内网 IP 格式无效 (例如: 192.168.1.100)。')

# MASQUERADE 管理表单
class MasqueradeForm(FlaskForm):
    submit = SubmitField('添加/确保 MASQUERADE')

@app.route('/', methods=['GET', 'POST'])
def index():
    dnat_form = AddDnatRuleForm()
    masq_form = MasqueradeForm()

    # 处理 POST 请求
    if request.method == 'POST':
        if 'add_dnat_submit' in request.form: # 检查DNAT表单的提交按钮名
             if dnat_form.validate_on_submit():
                 # 构建 DNAT iptables 命令
                 cmd = [
                     'iptables', '-t', 'nat', '-A', 'PREROUTING',
                     '-i', PUBLIC_INTERFACE,
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

             # 如果验证失败，错误会在渲染模板时显示

        elif 'delete_rule_submit' in request.form: # 检查删除按钮的提交名
             line_number = request.form.get('line_number')
             if line_number:
                 try:
                      line_number = int(line_number)
                      cmd = ['iptables', '-t', 'nat', '-D', 'PREROUTING', line_number]
                      ok, msg = execute_iptables_command(cmd)
                      if ok:
                          flash(f'规则 (行号 {line_number}) 删除成功。', 'success')
                      else:
                          flash(f'删除规则 (行号 {line_number}) 失败: {msg}', 'danger')
                 except ValueError:
                      flash('无效的规则行号。', 'danger')
             else:
                  flash('未能获取规则行号进行删除。', 'danger')

        elif 'masq_submit' in request.form: # 检查MASQUERADE表单的提交按钮名
             # 检查是否已存在 MASQUERADE 规则 (简化的检查，只看目标和出站接口)
             # 实际应该遍历规则列表，更精确匹配
             cmd_check = ['iptables', '-t', 'nat', '-L', 'POSTROUTING', '-v', '-n']
             ok_check, output_check, err_check = execute_iptables_command(cmd_check)
             masq_exists = False
             if ok_check:
                  for line in output_check.splitlines():
                      if f'MASQUERADE all -- any {PUBLIC_INTERFACE}' in line: # 简化匹配，可能不精确
                          masq_exists = True
                          break

             if masq_exists:
                  flash(f"MASQUERADE 规则 ({PUBLIC_INTERFACE}) 已存在。", 'info')
             else:
                  # 构建 MASQUERADE iptables 命令
                  cmd_add_masq = [
                      'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                      '-o', PUBLIC_INTERFACE, # 在出站接口应用
                      '-j', 'MASQUERADE'
                  ]
                  ok_add, msg_add = execute_iptables_command(cmd_add_masq)

                  if ok_add:
                      flash('MASQUERADE 规则添加成功并已应用。', 'success')
                  else:
                      flash(f'添加 MASQUERADE 规则失败: {msg_add}', 'danger')

        # 重定向以防止刷新重复提交
        return redirect(url_for('index'))

    # 处理 GET 请求
    ok, rules, error_msg = list_nat_prerouting_rules()
    if not ok:
         flash(f"无法加载当前的 NAT 规则: {error_msg}", 'danger')
         # 仍尝试渲染页面，规则列表可能为空

    return render_template('index.html', dnat_form=dnat_form, masq_form=masq_form, rules=rules, public_interface=PUBLIC_INTERFACE)

@app.route('/clear_all_prerouting', methods=['POST'])
def clear_all_prerouting():
    """清空 NAT PREROUTING 链的所有规则"""
    cmd = ['iptables', '-t', 'nat', '-F', 'PREROUTING']
    ok, msg = execute_iptables_command(cmd)
    if ok:
        flash('成功清空 NAT PREROUTING 链的所有规则。', 'success')
    else:
        flash(f'清空 NAT PREROUTING 链失败: {msg}', 'danger')
    return redirect(url_for('index'))

# 启动时的初始化，不使用 flash
if __name__ == '__main__':
    print("\n!!! 安全警告 !!!")
    print("此应用管理系统防火墙规则，可能需要 root 权限才能执行 iptables 命令。")
    print("在生产环境中以 root 运行 Web 服务器是 非 常 危 险 的。")
    print("此设置仅用于学习/演示，且规则不持久化，主机重启后会丢失。")
    print("!!! 安全警告 !!!\n")

    # 启动时不加载或保存规则，只依赖用户通过 Web 界面操作当前状态
    # 你可以根据需要在此处添加默认规则（如果需要持久化，需要保存到文件并在启动时加载）
    # 例如: execute_iptables_command(['iptables', ...])

    app.run(host='0.0.0.0', port=5000)
