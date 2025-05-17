import os
import subprocess
import shlex
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Optional, ValidationError

PUBLIC_INTERFACE = 'enp7s0' # 硬编码公网网卡名称

app = Flask(__name__)
# 生产环境中务必修改此密钥，用于保护会话信息
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_fallback')

def execute_iptables_command(cmd):
    safe_cmd = []
    for arg in cmd:
         # 基础安全检查，防止明显注入字符
         # 注意：这不是完全安全的输入过滤，生产环境需要更完善的验证
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
        # iptables 成功时通常没有 stdout/stderr
        print("命令执行成功。")
        return True, "成功"
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败，退出码 {e.returncode}")
        print("Stderr:", e.stderr.strip()) # 打印错误输出
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
    # print(f"正在执行命令: {' '.join(cmd)}") # 避免日志重复

    try:
        # 同样需要 root 权限读取规则
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
        output_lines = result.stdout.splitlines()

        rules = []
        # 解析 iptables -L --line-numbers -v -n 的输出
        # 输出格式大致为:
        # Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
        # num   pkts bytes target     prot opt in     out     source               destination
        # 1        0     0 DNAT       tcp  --  enp7s0 any     0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:192.168.1.100:80
        # 2        0     0 DNAT       udp  --  enp7s0 any     0.0.0.0/0            0.0.0.0/0            udp dpt:53 to:192.168.1.200:53

        parsing_rules = False
        for line in output_lines:
            line = line.strip()
            if line.startswith('num'): # 找到表头，之后是规则行
                parsing_rules = True
                continue
            if not parsing_rules or not line:
                 continue # 跳过头部信息和空行

            # 尝试解析规则行
            parts = line.split()
            # 检查是否至少包含基本字段 num, pkts, bytes, target, prot, opt, in, out, source, destination
            if len(parts) < 10:
                 continue # 不是标准的规则行

            try:
                 line_num = int(parts[0])
                 target = parts[3]
                 prot = parts[4]
                 in_if = parts[5]
                 out_if = parts[6]
                 # source = parts[7] # 不在简化列表中显示
                 # destination = parts[8] # 不在简化列表中显示

                 # 只解析和显示我们添加的那种简单的 DNAT 规则：
                 # 在 PREROUTING 链，目标是 DNAT，入站接口匹配，有协议，有目标端口和 to-destination
                 if target == 'DNAT' and in_if in [PUBLIC_INTERFACE, 'any'] and prot in ['tcp', 'udp']:
                      # 进一步解析扩展字段
                      extra_info = " ".join(parts[9:])
                      dport = '-'
                      to_destination = '-'

                      # 查找 dpt:
                      dport_match = None
                      try:
                          # Use regex for more robust parsing if needed, simple split here
                          # Find 'dpt:' and the part immediately following it
                          dport_str_index = extra_info.find('dpt:')
                          if dport_str_index != -1:
                              dport_part = extra_info[dport_str_index + 4:].split(' ')[0] # Get the port part
                              # The port part might be just a number or number/protocol (e.g. 80, 53/udp)
                              dport = dport_part.split('/')[0] # Get just the number

                      except Exception as e:
                          print(f"Warning: Failed to parse dport from '{extra_info}': {e}")


                      # 查找 to:
                      to_match = None
                      try:
                          # Find 'to:' and the part immediately following it
                          to_dest_str_index = extra_info.find('to:')
                          if to_dest_str_index != -1:
                               to_destination = extra_info[to_dest_str_index + 3:].split(' ')[0] # Get the destination part
                      except Exception as e:
                          print(f"Warning: Failed to parse to:destination from '{extra_info}': {e}")


                      rules.append({
                           'line_number': line_num,
                           'protocol': prot,
                           'in_interface': in_if,
                           'dport': dport,
                           'to_destination': to_destination,
                           # 描述无法从 iptables 获取，这里不显示
                      })

            except (ValueError, IndexError) as e:
                 # print(f"Warning: Failed to parse iptables line '{line}': {e}") # 打印所有解析失败的行很吵，可以按需开启
                 continue # Skip lines that don't match expected format or have parsing errors

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
    form_id = HiddenField('form_id', default='add_masq') # 用于区分表单提交
    submit = SubmitField('添加/确保 MASQUERADE')

@app.route('/', methods=['GET', 'POST'])
def index():
    # 在 POST 请求时，将提交的数据传递给表单以便验证和访问数据
    dnat_form = AddDnatRuleForm(request.form) if request.method == 'POST' else AddDnatRuleForm()
    masq_form = MasqueradeForm(request.form) if request.method == 'POST' else MasqueradeForm()

    # 处理 POST 请求
    if request.method == 'POST':
        # 通过 hidden form_id 判断是哪个表单提交的
        form_id = request.form.get('form_id')

        if form_id == 'add_dnat':
             if dnat_form.validate():
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
             else:
                  # 验证失败，错误将由模板显示
                  flash('添加规则失败，请检查输入。', 'danger')

        elif form_id == 'add_masq':
             if masq_form.validate(): # 验证 CSRF token
                 # 检查是否已存在 MASQUERADE 规则 (简化的检查)
                 # 更精确的检查需要解析 iptables -L POSTROUTING 输出
                 # 这里的实现是：即使已存在，也尝试添加，iptables 会将重复规则添加到链末尾
                 # 如果需要确保唯一，需要更复杂的检查或使用 iptables-restore
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
             else:
                  flash('MASQUERADE 表单验证失败。', 'danger') # CSRF 验证失败等

        elif 'delete_rule_submit' in request.form: # 通过删除按钮的 name 判断
             line_number = request.form.get('line_number')
             if line_number:
                 try:
                      line_number = int(line_number)
                      # 使用行号删除规则 (注意：行号可能因其他规则变动而变化)
                      cmd = ['iptables', '-t', 'nat', '-D', 'PREROUTING', str(line_number)] # 行号作为字符串传递
                      ok, msg = execute_iptables_command(cmd)
                      if ok:
                          flash(f'规则 (行号 {line_number}) 删除成功。', 'success')
                      else:
                          flash(f'删除规则 (行号 {line_number}) 失败: {msg}', 'danger')
                 except ValueError:
                      flash('无效的规则行号。', 'danger')
             else:
                  flash('未能获取规则行号进行删除。', 'danger')

        else:
             # 如果提交的 POST 没有 form_id 或 delete_rule_submit，则为未知请求
             flash('未知操作请求。', 'warning')


        # 重定向到首页以防止刷新重复提交，并触发 GET 请求重新加载规则列表
        return redirect(url_for('index'))

    # 处理 GET 请求
    # 在 GET 请求时，list_nat_prerouting_rules 会获取当前的规则列表
    ok, rules, error_msg = list_nat_prerouting_rules()
    if not ok:
         flash(f"无法加载当前的 NAT PREROUTING 规则: {error_msg}", 'danger')
         # 仍尝试渲染页面，规则列表可能为空 []

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


# 启动时的初始化，只打印警告信息，不执行 iptables 操作
if __name__ == '__main__':
    print("\n!!! 安全警告 !!!")
    print("此应用管理系统防火墙规则，可能需要 root 权限才能执行 iptables 命令。")
    print("在生产环境中以 root 运行 Web 服务器是 非 常 危 险 的。")
    print("此设置仅用于学习/演示，且规则不持久化，主机重启后会丢失。")
    print("!!! 安全警告 !!!\n")

    # app.run() 函数会自己处理请求和应用上下文
    app.run(host='0.0.0.0', port=5000)
