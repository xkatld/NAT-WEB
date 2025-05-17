import os
import subprocess
import shlex
import re
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Optional, ValidationError

PUBLIC_INTERFACE = os.environ.get('PUBLIC_INTERFACE', 'enp7s0')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_fallback')

def execute_iptables_command(cmd):
    forbidden_chars = ['&', '|', ';', '`', '$', '>', '<', '(', ')', '{', '}', '\\', '*']
    for arg in cmd:
         arg_str = str(arg)
         if any(c in arg_str for c in forbidden_chars):
             print(f"SECURITY ALERT: Potential command injection attempt detected in argument: {arg_str}")
             return False, f"错误：命令参数中包含无效字符: {arg_str}"

    print(f"执行命令: {' '.join(shlex.quote(str(arg)) for arg in cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
        if result.stderr:
            print("Stderr:", result.stderr.strip())
        print("命令成功。")
        return True, result.stderr.strip() if result.stderr else "成功"
    except subprocess.CalledProcessError as e:
        print(f"命令失败，退出码 {e.returncode}")
        print("Stderr:", e.stderr.strip())
        return False, f"命令失败 ({e.returncode}): {e.stderr.strip()}"
    except FileNotFoundError:
         print("未找到 iptables 命令。")
         return False, "未找到 iptables 命令"
    except Exception as e:
         print(f"未知错误: {e}")
         return False, f"未知错误: {e}"

def list_nat_rules(table, chain):
    cmd = ['iptables', '-t', table, '-L', chain, '-v', '-n', '--line-numbers']
    print(f"列出规则: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
        output_lines = result.stdout.splitlines()

        rules = []
        header_found = False
        for line in output_lines:
            line = line.strip()
            if line.startswith('Chain'):
                continue
            if line.startswith('num'):
                 header_found = True
                 continue
            if not header_found or not line:
                 continue

            parts = line.split(maxsplit=9)

            if len(parts) < 10 or not parts[0].isdigit():
                 continue

            try:
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
                     'to_destination': None
                 }

                 if target == 'DNAT':
                      to_match = re.search(r'to:([\w\d\.:-]+)', extra_info)
                      if to_match:
                           rule_data['to_destination'] = to_match.group(1)

                 rules.append(rule_data)

            except (ValueError, IndexError) as e:
                 print(f"解析 iptables 行失败 '{line}': {e}")
                 continue

        return True, rules, ""

    except subprocess.CalledProcessError as e:
        error_msg = f"列出规则失败: {e.stderr.strip()}"
        print(error_msg)
        return False, [], error_msg
    except FileNotFoundError:
         error_msg = "未找到 iptables 命令。"
         print(error_msg)
         return False, [], error_msg
    except Exception as e:
         error_msg = f"列出规则时未知错误: {e}"
         print(error_msg)
         return False, [], error_msg

def get_interface_ip(interface_name):
    cmd = ['ip', 'addr', 'show', interface_name]
    print(f"获取网卡IP: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace')
        # 查找 inet ... /...
        match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', result.stdout)
        if match:
            print(f"获取到IP: {match.group(1)}")
            return match.group(1)
        else:
            print(f"网卡 {interface_name} 未找到 IPv4 地址。")
            return "未找到IP"
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        print(f"获取网卡 {interface_name} IP失败: {e}")
        return "获取失败"


class AddDnatRuleForm(FlaskForm):
    form_id = HiddenField('form_id', default='add_dnat')
    protocol = SelectField('协议', choices=[('tcp', 'TCP'), ('udp', 'UDP')], validators=[DataRequired('协议是必填项')])
    public_port = StringField('主机端口', validators=[DataRequired('主机端口是必填项')])
    internal_ip = StringField('内网 IP', validators=[DataRequired('内网 IP 是必填项')])
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
         parts = field.data.split('.')
         if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
              raise ValidationError('内网 IP 格式无效。')


@app.route('/', methods=['GET', 'POST'])
def index():
    dnat_form = AddDnatRuleForm()

    if request.method == 'POST':
        form_id = request.form.get('form_id')

        if form_id == 'add_dnat' and dnat_form.validate_on_submit():
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
                flash('规则添加成功。', 'success')
            else:
                flash(f'添加规则失败: {msg}', 'danger')

        elif 'delete_rule_submit' in request.form:
             line_number_str = request.form.get('line_number')
             if line_number_str:
                 try:
                      line_number = int(line_number_str)
                      cmd = ['iptables', '-t', 'nat', '-D', 'PREROUTING', str(line_number)]
                      ok, msg = execute_iptables_command(cmd)
                      if ok:
                          flash(f'规则 (行号 {line_number}) 删除成功。', 'success')
                      else:
                          flash(f'删除规则 (行号 {line_number}) 失败: {msg}', 'danger')
                 except ValueError:
                      flash('无效规则行号。', 'danger')
                 except Exception as e:
                      flash(f'删除规则时意外错误: {e}', 'danger')
             else:
                  flash('未能获取规则行号。', 'danger')

        else:
             flash('未知请求。', 'warning')

        return redirect(url_for('index'))

    ok, prerouting_rules, error_msg = list_nat_rules('nat', 'PREROUTING')
    if not ok:
         flash(f"无法加载规则: {error_msg}", 'danger')

    interface_ip = get_interface_ip(PUBLIC_INTERFACE)

    return render_template('index.html',
                           dnat_form=dnat_form,
                           rules=prerouting_rules,
                           public_interface=PUBLIC_INTERFACE,
                           interface_ip=interface_ip)

@app.route('/clear_all_prerouting', methods=['POST'])
def clear_all_prerouting():
    form = FlaskForm(request.form)
    if not form.validate_on_submit():
         flash('安全验证失败。', 'danger')
         return redirect(url_for('index'))

    cmd = ['iptables', '-t', 'nat', '-F', 'PREROUTING']
    ok, msg = execute_iptables_command(cmd)
    if ok:
        flash('已清空 NAT PREROUTING 链规则。', 'success')
    else:
        flash(f'清空失败: {msg}', 'danger')
    return redirect(url_for('index'))


if __name__ == '__main__':
    print("\n!!! 安全警告 !!!")
    print("此应用可能需要 root 权限。直接以 root 运行 Web 服务器非常危险。")
    print(f"公网网卡: {PUBLIC_INTERFACE} (可通过环境变量 PUBLIC_INTERFACE 覆盖)")
    print("规则不持久化，重启后会丢失。")
    print("!!! 安全警告 !!!\n")

    app.run(host='0.0.0.0', port=5000, debug=True)
