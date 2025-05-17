import os
import subprocess
import shlex
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional, ValidationError

from models import db, NatRule

BASEDIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASEDIR, 'nat_rules.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_fallback')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def execute_iptables_command(cmd):
    safe_cmd = []
    for arg in cmd:
         if any(c in arg for c in ['&', '|', ';', '`', '$', '>', '<', '(', ')', '{', '}', '\\', '*']):
             print(f"SECURITY ALERT: Potential command injection attempt detected in argument: {arg}")
             return False, f"错误：命令参数中包含无效字符: {arg}"
         safe_cmd.append(arg)

    print(f"正在执行命令: {' '.join(shlex.quote(arg) for arg in safe_cmd)}")

    try:
        result = subprocess.run(safe_cmd, check=True, capture_output=True, text=True, timeout=10)
        print("命令执行成功。")
        # print("Stdout:", result.stdout) # Optional detailed logging
        # print("Stderr:", result.stderr) # Optional detailed logging
        return True, "成功"
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败，退出码 {e.returncode}")
        # print("Stdout:", e.stdout) # Optional detailed logging
        # print("Stderr:", e.stderr) # Optional detailed logging
        return False, f"命令执行失败: {e.stderr.strip()}"
    except FileNotFoundError:
         print("未找到 iptables 命令。")
         return False, "未找到 iptables 命令"
    except Exception as e:
         print(f"发生未知错误: {e}")
         return False, f"发生未知错误: {e}"

def clear_nat_rules():
    chains_to_clear = ['PREROUTING', 'POSTROUTING', 'OUTPUT']
    messages = []
    all_ok = True
    for chain in chains_to_clear:
        cmd = ['iptables', '-t', 'nat', '-F', chain]
        ok, msg = execute_iptables_command(cmd)
        if ok:
            messages.append(f"成功清空链 {chain}。")
        else:
            messages.append(f"警告：清空链 {chain} 失败: {msg}")
            all_ok = False
    return all_ok, messages

def apply_all_rules_from_db():
    messages = []
    overall_ok = True

    clear_ok, clear_msgs = clear_nat_rules()
    messages.extend(clear_msgs)
    if not clear_ok:
        overall_ok = False

    rules = NatRule.query.all()
    success_count = 0
    fail_count = 0
    for rule in rules:
        cmd = rule.build_iptables_command_add()
        ok, msg = execute_iptables_command(cmd)
        rule_summary = f"规则ID {rule.id} ({rule.target} {rule.chain}): "
        if ok:
            messages.append(rule_summary + "应用成功。")
            success_count += 1
        else:
            messages.append(rule_summary + f"应用失败: {msg}")
            fail_count += 1
            overall_ok = False

    final_summary = f"总计：清空链 {'成功' if clear_ok else '失败'}，应用规则 成功={success_count}, 失败={fail_count}。"
    messages.insert(0, final_summary)

    return overall_ok, messages

class AddNatRuleForm(FlaskForm):
    chain = SelectField('链', choices=[
        ('PREROUTING', 'PREROUTING'),
        ('POSTROUTING', 'POSTROUTING'),
        ('OUTPUT', 'OUTPUT'),
    ], validators=[DataRequired('链是必填项')])
    protocol = SelectField('协议', choices=[
        ('', '任意/所有'),
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('icmp', 'ICMP'),
    ], default='')
    source = StringField('源 IP/网络 (-s)', validators=[Optional()])
    destination = StringField('目标 IP/网络 (-d)', validators=[Optional()])
    in_interface = StringField('入站接口 (-i)', validators=[Optional()])
    out_interface = StringField('出站接口 (-o)', validators=[Optional()])
    source_port = StringField('源端口 (--sport)', validators=[Optional()])
    destination_port = StringField('目标端口 (--dport)', validators=[Optional()])
    target = SelectField('目标动作', choices=[
        ('MASQUERADE', 'MASQUERADE'),
        ('DNAT', 'DNAT'),
        ('SNAT', 'SNAT'),
    ], validators=[DataRequired('目标动作是必填项')])
    to_destination = StringField('目标地址转换 (--to-destination)', validators=[Optional()])
    to_source = StringField('源地址转换 (--to-source)', validators=[Optional()])
    description = TextAreaField('描述', validators=[Optional()])
    submit = SubmitField('添加规则')

@app.route('/')
def index():
    rules = NatRule.query.all()
    return render_template('index.html', rules=rules)

@app.route('/add', methods=['GET', 'POST'])
def add_rule():
    form = AddNatRuleForm()
    if form.validate_on_submit():
        new_rule = NatRule(
            table='nat',
            chain=form.chain.data,
            protocol=form.protocol.data if form.protocol.data else None,
            source=form.source.data if form.source.data else None,
            destination=form.destination.data if form.destination.data else None,
            in_interface=form.in_interface.data if form.in_interface.data else None,
            out_interface=form.out_interface.data if form.out_interface.data else None,
            source_port=form.source_port.data if form.source_port.data else None,
            destination_port=form.destination_port.data if form.destination_port.data else None,
            target=form.target.data,
            to_destination=form.to_destination.data if form.to_destination.data else None,
            to_source=form.to_source.data if form.to_source.data else None,
            description=form.description.data if form.description.data else None
        )

        if new_rule.target == 'DNAT' and not new_rule.to_destination:
             flash('DNAT 目标动作需要填写“目标地址转换”。', 'warning')
             return render_template('add_rule.html', form=form)
        if new_rule.target == 'SNAT' and not new_rule.to_source:
             flash('SNAT 目标动作需要填写“源地址转换”。', 'warning')
             return render_template('add_rule.html', form=form)
        if new_rule.target == 'MASQUERADE' and new_rule.to_destination:
             flash('MASQUERADE 目标动作不需要填写“目标地址转换”。', 'warning')

        cmd = new_rule.build_iptables_command_add()
        ok, msg = execute_iptables_command(cmd)

        if ok:
            try:
                db.session.add(new_rule)
                db.session.commit()
                flash('规则已成功添加到数据库并应用。', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                flash(f'成功应用规则但保存到数据库失败: {e}。规则已激活但未保存！', 'danger')
                return redirect(url_for('index'))
        else:
            flash(f'使用 iptables 应用规则失败。规则未保存到数据库。错误: {msg}', 'danger')
            return render_template('add_rule.html', form=form)

    return render_template('add_rule.html', form=form)

@app.route('/delete/<int:rule_id>', methods=['POST'])
def delete_rule(rule_id):
    rule = NatRule.query.get_or_404(rule_id)

    cmd = rule.build_iptables_command_delete()
    ok, msg = execute_iptables_command(cmd)

    if ok:
        try:
            db.session.delete(rule)
            db.session.commit()
            flash('规则已成功从数据库和 iptables 中删除。', 'success')
        except Exception as e:
             db.session.rollback()
             flash(f'从 iptables 删除规则成功但从数据库删除失败: {e}。规则已失效但仍在数据库中！', 'danger')
    else:
        flash(f'使用 iptables 删除规则失败。规则仍在数据库中。错误: {msg}', 'danger')

    return redirect(url_for('index'))

@app.route('/apply_all', methods=['POST'])
def apply_all():
    overall_ok, messages = apply_all_rules_from_db()
    for msg in messages:
         flash(msg, 'success' if '成功' in msg and '失败' not in msg and '警告' not in msg else 'danger' if '失败' in msg else 'warning')
    if overall_ok:
         flash("所有规则应用过程完成。", 'success')
    else:
         flash("规则应用过程包含失败项，请检查警告/错误信息。", 'danger')
    return redirect(url_for('index'))

@app.before_request
def create_tables_on_first_request():
    if not os.path.exists(DB_PATH):
        print(f"未找到数据库文件 {DB_PATH}。正在创建数据库和表。")
        with app.app_context():
            db.create_all()
            print("数据库表已创建。")

    # 启动时的规则加载只在 __main__ 块处理一次
    pass


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # 确保数据库表在应用上下文内创建
        print("正在启动时从数据库应用规则...")
        overall_ok, messages = apply_all_rules_from_db() # 在应用上下文内调用
        print("\n--- 启动时规则应用报告 ---")
        for msg in messages:
            print(msg)
        print("-------------------------\n")
        if not overall_ok:
             print("警告: 启动时应用规则过程包含失败项。")


    print("\n!!! 安全警告 !!!")
    print("此应用很可能需要 root 权限才能执行 iptables 命令。")
    print("在生产环境中以 root 运行 Web 服务器是 非 常 危 险 的。")
    print("此设置仅用于学习/演示。")
    print("请在生产环境中使用生产级 WSGI 服务器和安全的特权执行机制。")
    print("!!! 安全警告 !!!\n")

    app.run(host='0.0.0.0', port=5000)
