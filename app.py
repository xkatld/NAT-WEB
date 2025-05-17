import os
import subprocess
import shlex
import re
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
    forbidden_chars = ['&', '|', ';', '`', '$', '>', '<', '(', ')', '{', '}', '\\', '*']
    for arg in cmd:
         arg_str = str(arg) # 确保参数是字符串以便检查
         if any(c in arg_str for c in forbidden_chars):
             print(f"SECURITY ALERT: Potential command injection attempt detected in argument: {arg_str}")
             return False, f"错误：命令参数中包含无效字符: {arg_str}"

    print(f"正在执行命令: {' '.join(shlex.quote(str(arg)) for arg in cmd)}")

    try:
        # 使用 root 权限执行 iptables
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
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
    cmd = ['iptables', '-t', table, '-L', chain, '-v', '-n', '--line-numbers']
    print(f"正在列出规则: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
        output_lines = result.stdout.splitlines()

        rules = []
        header_found = False
        for line in output_lines:
            line = line.strip()
            if line.startswith('Chain'):
                continue # 跳过 Chain 行
            if line.startswith('num'): # 找到表头
                 header_found = True
                 continue
            if not header_found or not line:
                 continue # 跳过头部信息、非规则行和空行

            # 尝试解析规则行 - 假设前10个字段是标准字段
            # num pkts bytes target prot opt in out source destination
            parts = line.split(maxsplit=9)

            if len(parts) < 10 or not parts[0].isdigit():
                 continue # 如果分割后少于10个部分，或者第一个部分不是数字（行号），则跳过

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
                 extra_info_parts = line.split()[10:] if len(line.split()) > 10 else []
                 extra_info = " ".join(extra_info_parts).strip()

                 rule_data = {
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
                     'extra_info': extra_info,
                     'to_destination': None # 用于DNAT显示
                 }

                 # 尝试为 DNAT 规则解析出 to:destination (仅为方便显示)
                 if target == 'DNAT':
                      to_match = re.search(r'to:([\w\d\.:-]+)', extra_info)
                      if to_match:
                           rule_data['to_destination'] = to_match.group(1)

                 rules.append(rule_data)

            except (ValueError, IndexError) as e:
                 print(f"Warning: Failed to parse iptables line '{line}': {e}")
                 continue # 继续解析下一行

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


@app.route('/', methods=['GET', 'POST'])
def index():
    dnat_form = AddDnatRuleForm() # 无论 GET 还是 POST 都创建表单实例

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

        elif 'delete_rule_submit' in request.form: # 通过删除按钮的 name 判断
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

        # 重定向到首页以防止刷新重复提交，并触发 GET 请求重新加载规则列表
        return redirect(url_for('index'))

    # 处理 GET 请求
    # 在 GET 请求时，list_nat_rules 会获取当前的规则列表
    ok, prerouting_rules, error_msg = list_nat_rules('nat', 'PREROUTING')
    if not ok:
         flash(f"无法加载当前的 NAT PREROUTING 规则: {error_msg}", 'danger')
         # 仍尝试渲染页面，规则列表可能为空 []

    return render_template('index.html',
                           dnat_form=dnat_form,
                           rules=prerouting_rules, # PREROUTING 规则
                           public_interface=PUBLIC_INTERFACE)


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


# 启动时的初始化，只打印警告信息
if __name__ == '__main__':
    print("\n!!! 安全警告 !!!")
    print("此应用管理系统防火墙规则，可能需要 root 权限才能执行 iptables 命令。")
    print("在生产环境中以 root 运行 Web 服务器是 非 常 危 险 的。")
    print(f"硬编码的公网网卡为: {PUBLIC_INTERFACE} (可通过环境变量 PUBLIC_INTERFACE 覆盖)")
    print("当前管理的规则不持久化，主机重启后会丢失，需要额外的系统服务来保存和恢复规则。")
    print("!!! 安全警告 !!!\n")

    # debug=True 仅用于开发环境，生产环境请禁用
    app.run(host='0.0.0.0', port=5000, debug=True) # 开发阶段开启 debug 方便排错
