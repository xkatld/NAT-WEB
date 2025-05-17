from flask import Flask, render_template, request, redirect, url_for, g, flash
import database
import firewall
import sys # Import sys for stderr

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_change_this' # Change this to a random secret key!

# Database initialization on app startup
@app.before_request
def before_request():
    database.get_db()

@app.teardown_request
def teardown_request(exception):
    database.close_db(exception)

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    database.init_db()
    print('Initialized the database.')

@app.route('/')
def index():
    """Display all NAT rules."""
    rules = database.get_all_rules()
    return render_template('index.html', rules=rules)

@app.route('/add', methods=('GET', 'POST'))
def add_rule():
    """Add a new NAT rule."""
    if request.method == 'POST':
        description = request.form['description']
        lxc_id = request.form['lxc_id']
        container_port = request.form['container_port']
        external_port = request.form['external_port']
        protocol = request.form['protocol']
        external_ip = request.form.get('external_ip', '0.0.0.0')
        enabled = 'enabled' in request.form # Checkbox value

        # Basic validation
        if not description or not lxc_id or not container_port or not external_port or not protocol:
            flash('All fields are required except External IP (defaults to 0.0.0.0).', 'error')
        else:
            try:
                lxc_id = int(lxc_id)
                container_port = int(container_port)
                external_port = int(external_port)
                if lxc_id < 100 or container_port < 1 or container_port > 65535 or external_port < 1 or external_port > 65535:
                     flash('Invalid ID or port number.', 'error')
                     return render_template('form.html', rule=request.form) # Render form with user input
                if protocol not in ['tcp', 'udp', 'both']:
                     flash('Invalid protocol.', 'error')
                     return render_template('form.html', rule=request.form) # Render form with user input

                rule_id = database.add_rule(description, lxc_id, container_port, external_port, protocol, external_ip, enabled)

                if rule_id:
                    flash(f'Rule "{description}" added successfully.', 'success')
                    # Automatically apply rules after adding/modifying
                    success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
                    if failed_count > 0:
                         flash(f'Warning: Failed to apply {failed_count} rule(s) to firewall. Check console output for details.', 'error')
                         for err in errors:
                             print(err, file=sys.stderr) # Log errors to stderr
                    else:
                         flash('Firewall rules updated.', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Error adding rule. Likely a duplicate external IP/Port/Protocol combination.', 'error')

            except ValueError:
                 flash('Invalid number format for ID or ports.', 'error')
            except Exception as e:
                 flash(f'An unexpected error occurred: {e}', 'error')


    return render_template('form.html')

@app.route('/edit/<int:rule_id>', methods=('GET', 'POST'))
def edit_rule(rule_id):
    """Edit an existing NAT rule."""
    rule = database.get_rule(rule_id)

    if rule is None:
        flash('Rule not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        description = request.form['description']
        lxc_id = request.form['lxc_id']
        container_port = request.form['container_port']
        external_port = request.form['external_port']
        protocol = request.form['protocol']
        external_ip = request.form.get('external_ip', '0.0.0.0')
        enabled = 'enabled' in request.form

        # Basic validation
        if not description or not lxc_id or not container_port or not external_port or not protocol:
            flash('All fields are required except External IP.', 'error')
        else:
             try:
                lxc_id = int(lxc_id)
                container_port = int(container_port)
                external_port = int(external_port)
                if lxc_id < 100 or container_port < 1 or container_port > 65535 or external_port < 1 or external_port > 65535:
                     flash('Invalid ID or port number.', 'error')
                     return render_template('form.html', rule=request.form) # Render form with user input
                if protocol not in ['tcp', 'udp', 'both']:
                     flash('Invalid protocol.', 'error')
                     return render_template('form.html', rule=request.form) # Render form with user input

                if database.update_rule(rule_id, description, lxc_id, container_port, external_port, protocol, external_ip, enabled):
                    flash(f'Rule ID {rule_id} updated successfully.', 'success')
                    # Automatically apply rules after adding/modifying
                    success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
                    if failed_count > 0:
                         flash(f'Warning: Failed to apply {failed_count} rule(s) to firewall. Check console output for details.', 'error')
                         for err in errors:
                             print(err, file=sys.stderr) # Log errors to stderr
                    else:
                         flash('Firewall rules updated.', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Error updating rule. Likely a duplicate external IP/Port/Protocol combination.', 'error')

             except ValueError:
                 flash('Invalid number format for ID or ports.', 'error')
             except Exception as e:
                 flash(f'An unexpected error occurred: {e}', 'error')


    return render_template('form.html', rule=rule)

@app.route('/delete/<int:rule_id>', methods=('POST',))
def delete_rule(rule_id):
    """Delete a NAT rule."""
    # Check if rule exists before deleting
    rule = database.get_rule(rule_id)
    if rule is None:
        flash('Rule not found.', 'error')
        return redirect(url_for('index'))

    database.delete_rule(rule_id)
    flash(f'Rule ID {rule_id} deleted successfully.', 'success')

    # Automatically apply rules after deleting
    success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
    if failed_count > 0:
         flash(f'Warning: Failed to apply {failed_count} rule(s) to firewall after deletion. Check console output for details.', 'error')
         for err in errors:
             print(err, file=sys.stderr) # Log errors to stderr
    else:
         flash('Firewall rules updated.', 'success')


    return redirect(url_for('index'))

@app.route('/toggle/<int:rule_id>', methods=('POST',))
def toggle_rule(rule_id):
    """Toggle the enabled status of a rule."""
    rule = database.get_rule(rule_id)
    if rule is None:
        flash('Rule not found.', 'error')
        return redirect(url_for('index'))

    new_status = database.toggle_rule_enabled(rule_id)
    if new_status is not None:
        status_text = "Enabled" if new_status else "Disabled"
        flash(f'Rule ID {rule_id} status toggled to "{status_text}".', 'success')

        # Automatically apply rules after toggling
        success_count, failed_count, errors = firewall.apply_all_rules(database.get_all_rules())
        if failed_count > 0:
             flash(f'Warning: Failed to apply {failed_count} rule(s) to firewall after toggling. Check console output for details.', 'error')
             for err in errors:
                 print(err, file=sys.stderr) # Log errors to stderr
        else:
             flash('Firewall rules updated.', 'success')

    else:
        flash('Error toggling rule status.', 'error')

    return redirect(url_for('index'))


@app.route('/apply_all', methods=('POST',))
def apply_all():
    """Apply all enabled rules from DB to the firewall."""
    rules = database.get_all_rules()
    success_count, failed_count, errors = firewall.apply_all_rules(rules)

    if failed_count == 0:
        flash(f'Successfully applied {success_count} enabled rule(s) to firewall.', 'success')
    elif success_count == 0:
        flash(f'Failed to apply all {failed_count} enabled rule(s) to firewall. Check console output.', 'error')
        for err in errors:
            print(err, file=sys.stderr) # Log errors to stderr
    else:
        flash(f'Applied {success_count} rule(s), but failed to apply {failed_count} rule(s). Check console output.', 'error')
        for err in errors:
            print(err, file=sys.stderr) # Log errors to stderr


    return redirect(url_for('index'))

# To run the app (for development)
if __name__ == '__main__':
    # Make sure the database is initialized
    with app.app_context():
        database.init_db()
        # Optional: Apply rules on startup
        print("Applying rules on startup...")
        firewall.apply_all_rules(database.get_all_rules())


    # WARNING: Running debug=True in production is DANGEROUS!
    # WARNING: Running app.run() as root is DANGEROUS!
    # Use a proper WSGI server (like Gunicorn/uWSGI) and configure sudo for firewall commands in production.
    app.run(host='0.0.0.0', port=5000, debug=True)
