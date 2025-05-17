from flask import Flask, render_template, request, redirect, url_for, g, flash
import database
import firewall
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_change_this'

@app.before_request
def before_request():
    database.get_db()

@app.teardown_request
def teardown_request(exception):
    database.close_db(exception)

@app.cli.command('initdb')
def initdb_command():
    database.init_db()
    print('数据库初始化命令执行完成。')

@app.route('/')
def index():
    rules = database.get_all_rules()
    return render_template('index.html', rules=rules)

@app.route('/add', methods=('GET', 'POST'))
def add_rule():
    if request.method == 'POST':
        description = request.form['description']
        lxc_id = request.form['lxc_id']
        container_port = request.form['container_port']
        external_port = request.form['external_port']
        protocol = request.form['protocol']
        external_ip = request.form.get('external_ip', '0.0.0.0')
        enabled = 'enabled' in request.form

        if not description or not lxc_id or not container_port or not external_port or not protocol:
            flash('除了外部 IP（默认为 0.0.0.0），所有字段都是必填的。', 'error')
        else:
            try:
                lxc_id = int(lxc_id)
                container_port = int(container_port)
                external_port = int(external_port)
                if lxc_id < 100 or container_port < 1 or container_port > 65535 or external_port < 1 or external_port > 65535:
                     flash('无效的 ID 或端口号。', 'error')
                     return render_template('form.html', rule=request.form)
                if protocol not in ['tcp', 'udp', 'both']:
                     flash('无效的协议。', 'error')
                     return render_template('form.html', rule=request.form)

                rule_id = database.add_rule(description, lxc_id, container_port, external_port, protocol, external_ip, enabled)

                if rule_id:
                    flash(f'规则 "{description}" 添加成功。', 'success')
                    success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
                    if failed_count > 0:
                         flash(f'警告：有 {failed_count} 条规则未能应用到防火墙。请检查控制台输出获取详细信息。', 'error')
                         for err in errors:
                             print(err, file=sys.stderr)
                    else:
                         flash('防火墙规则已更新。', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('添加规则失败。可能存在重复的外部 IP/端口/协议组合。', 'error')

            except ValueError:
                 flash('ID 或端口号格式无效。', 'error')
            except Exception as e:
                 flash(f'发生未知错误：{e}', 'error')


    return render_template('form.html')

@app.route('/edit/<int:rule_id>', methods=('GET', 'POST'))
def edit_rule(rule_id):
    rule = database.get_rule(rule_id)

    if rule is None:
        flash('未找到规则。', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        description = request.form['description']
        lxc_id = request.form['lxc_id']
        container_port = request.form['container_port']
        external_port = request.form['external_port']
        protocol = request.form['protocol']
        external_ip = request.form.get('external_ip', '0.0.0.0')
        enabled = 'enabled' in request.form

        if not description or not lxc_id or not container_port or not external_port or not protocol:
            flash('除了外部 IP，所有字段都是必填的。', 'error')
        else:
             try:
                lxc_id = int(lxc_id)
                container_port = int(container_port)
                external_port = int(external_port)
                if lxc_id < 100 or container_port < 1 or container_port > 65535 or external_port < 1 or external_port > 65535:
                     flash('无效的 ID 或端口号。', 'error')
                     return render_template('form.html', rule=request.form)
                if protocol not in ['tcp', 'udp', 'both']:
                     flash('无效的协议。', 'error')
                     return render_template('form.html', rule=request.form)

                if database.update_rule(rule_id, description, lxc_id, container_port, external_port, protocol, external_ip, enabled):
                    flash(f'规则 ID {rule_id} 更新成功。', 'success')
                    success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
                    if failed_count > 0:
                         flash(f'警告：有 {failed_count} 条规则未能应用到防火墙。请检查控制台输出获取详细信息。', 'error')
                         for err in errors:
                             print(err, file=sys.stderr)
                    else:
                         flash('防火墙规则已更新。', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('更新规则失败。可能存在重复的外部 IP/端口/协议组合。', 'error')

             except ValueError:
                 flash('ID 或端口号格式无效。', 'error')
             except Exception as e:
                 flash(f'发生未知错误：{e}', 'error')

    return render_template('form.html', rule=rule)

@app.route('/delete/<int:rule_id>', methods=('POST',))
def delete_rule(rule_id):
    rule = database.get_rule(rule_id)
    if rule is None:
        flash('未找到规则。', 'error')
        return redirect(url_for('index'))

    database.delete_rule(rule_id)
    flash(f'规则 ID {rule_id} 删除成功。', 'success')

    success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
    if failed_count > 0:
         flash(f'警告：删除后有 {failed_count} 条规则未能应用到防火墙。请检查控制台输出获取详细信息。', 'error')
         for err in errors:
             print(err, file=sys.stderr)
    else:
         flash('防火墙规则已更新。', 'success')

    return redirect(url_for('index'))

@app.route('/toggle/<int:rule_id>', methods=('POST',))
def toggle_rule(rule_id):
    rule = database.get_rule(rule_id)
    if rule is None:
        flash('未找到规则。', 'error')
        return redirect(url_for('index'))

    new_status = database.toggle_rule_enabled(rule_id)
    if new_status is not None:
        status_text = "已启用" if new_status else "已禁用"
        flash(f'规则 ID {rule_id} 状态已切换为 "{status_text}"。', 'success')

        success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
        if failed_count > 0:
             flash(f'警告：切换状态后有 {failed_count} 条规则未能应用到防火墙。请检查控制台输出获取详细信息。', 'error')
             for err in errors:
                 print(err, file=sys.stderr)
        else:
             flash('防火墙规则已更新。', 'success')

    else:
        flash('切换规则状态失败。', 'error')

    return redirect(url_for('index'))


@app.route('/apply_all', methods=('POST',))
def apply_all():
    rules = database.get_all_rules()
    success_count, failed_count, errors = firewall.apply_all_rules(rules)

    if failed_count == 0:
        flash(f'成功应用 {success_count} 条已启用规则到防火墙。', 'success')
    elif success_count == 0:
        flash(f'所有 {failed_count} 条已启用规则均未能应用到防火墙。请检查控制台输出。', 'error')
        for err in errors:
            print(err, file=sys.stderr)
    else:
        flash(f'应用了 {success_count} 条规则，但有 {failed_count} 条规则未能应用。请检查控制台输出。', 'error')
        for err in errors:
            print(err, file=sys.stderr)

    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        database.init_db()
        print("启动时应用规则...")
        firewall.apply_all_rules(database.get_all_rules())

    app.run(host='0.0.0.0', port=5000, debug=True)
