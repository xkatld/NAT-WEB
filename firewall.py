import subprocess
import sys
import time

# Define the custom iptables chain managed by this app
NAT_CHAIN = "PVE_LXC_NAT"
# A comment to identify rules managed by this app
RULE_COMMENT_PREFIX = "pvelxcnat:"

def _run_command(cmd):
    """Helper to run shell commands safely."""
    print(f"Executing command: {' '.join(cmd)}")
    try:
        # Use check=True to raise CalledProcessError on non-zero exit codes
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"Error: Command not found. Make sure iptables and pct are installed and in the PATH.", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}", file=sys.stderr)
        print("STDOUT:", e.stdout, file=sys.stderr)
        print("STDERR:", e.stderr, file=sys.stderr)
        # Specific error check for iptables chain already exists/does not exist
        if b"Chain already exists" in e.stderr:
            print("Info: iptables chain already exists.")
        elif b"No chain/target/match by that name" in e.stderr:
             print("Info: iptables chain does not exist.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

def _ensure_nat_chain():
    """Ensure the custom NAT chain and jump rule exist."""
    print(f"Ensuring iptables chain '{NAT_CHAIN}' exists...")
    # Create the chain if it doesn't exist
    _run_command(["sudo", "iptables", "-N", NAT_CHAIN])
    # Check if the jump rule from PREROUTING exists
    # Need to list rules and check for the jump rule
    existing_rules = _run_command(["sudo", "iptables", "-S", "PREROUTING"])
    jump_rule_spec = f"-A PREROUTING -j {NAT_CHAIN}"
    if existing_rules is None or jump_rule_spec not in existing_rules.splitlines():
        print(f"Adding jump rule to {NAT_CHAIN} from PREROUTING...")
        # Add the jump rule to PREROUTING at the beginning (-I 1)
        _run_command(["sudo", "iptables", "-I", "PREROUTING", "-j", NAT_CHAIN])
    else:
        print("Jump rule already exists.")

def _clear_nat_chain():
    """Flush all rules from the custom NAT chain."""
    print(f"Flushing rules in chain '{NAT_CHAIN}'...")
    _run_command(["sudo", "iptables", "-F", NAT_CHAIN])

def _get_lxc_ip(lxc_id):
    """Get the current IP address of an LXC container using pct exec."""
    print(f"Getting IP for LXC {lxc_id}...")
    # Command to get the first IPv4 address on eth0
    # Requires root/sudo to run pct exec
    cmd = ["sudo", "pct", "exec", str(lxc_id), "--", "ip", "-4", "addr", "show", "eth0"]
    output = _run_command(cmd)

    if output:
        # Parse the output to find the IP address
        for line in output.splitlines():
            if ' inet ' in line:
                parts = line.split()
                # Find 'inet' and take the next element (ip/mask)
                try:
                    inet_index = parts.index('inet')
                    ip_with_mask = parts[inet_index + 1]
                    ip = ip_with_mask.split('/')[0]
                    print(f"Found IP: {ip} for LXC {lxc_id}")
                    return ip
                except (ValueError, IndexError):
                    print(f"Could not parse IP line: {line}", file=sys.stderr)
        print(f"No IPv4 address found on eth0 for LXC {lxc_id}.", file=sys.stderr)
    else:
        print(f"Failed to get network info for LXC {lxc_id}.", file=sys.stderr)

    return None # IP not found or error


def _build_iptables_rule_cmd(rule, container_ip):
    """Build the iptables command list for a single rule."""
    # iptables -A PVE_LXC_NAT -d <external_ip> -p <protocol> --dport <external_port> -j DNAT --to-destination <container_ip>:<container_port> -m comment --comment "pvelxcnat:<rule_id>"

    cmd = [
        "sudo", "iptables", "-A", NAT_CHAIN,
        "-d", rule['external_ip'],
        "-p", rule['protocol'].lower() if rule['protocol'].lower() != 'both' else 'tcp', # iptables needs specific proto
        "--dport", str(rule['external_port']),
        "-j", "DNAT",
        "--to-destination", f"{container_ip}:{rule['container_port']}",
        "-m", "comment", "--comment", f"{RULE_COMMENT_PREFIX}{rule['id']}"
    ]

    # If protocol is 'both', add the UDP rule too
    if rule['protocol'].lower() == 'both':
         cmd_udp = [
            "sudo", "iptables", "-A", NAT_CHAIN,
            "-d", rule['external_ip'],
            "-p", "udp",
            "--dport", str(rule['external_port']),
            "-j", "DNAT",
            "--to-destination", f"{container_ip}:{rule['container_port']}",
            "-m", "comment", "--comment", f"{RULE_COMMENT_PREFIX}{rule['id']}"
         ]
         return [cmd, cmd_udp] # Return a list of commands if 'both'
    else:
        return [cmd] # Return a list containing a single command


def apply_all_rules(rules_from_db):
    """
    Apply all enabled rules from the database to the firewall.
    This clears the custom chain and re-adds all enabled rules.
    """
    print("Applying all enabled rules...")
    _ensure_nat_chain()
    _clear_nat_chain()

    success_count = 0
    failed_count = 0
    errors = []

    # Process enabled rules
    enabled_rules = [rule for rule in rules_from_db if rule['enabled']]

    if not enabled_rules:
        print("No enabled rules to apply.")
        return 0, 0, [] # success, failed, errors

    print(f"Found {len(enabled_rules)} enabled rules to apply.")

    for rule in enabled_rules:
        container_ip = _get_lxc_ip(rule['lxc_id'])
        if container_ip:
            commands = _build_iptables_rule_cmd(rule, container_ip)
            applied_successfully = True
            for cmd in commands:
                if _run_command(cmd) is None:
                    applied_successfully = False
                    errors.append(f"Failed to apply rule ID {rule['id']}: {' '.join(cmd)}")
            if applied_successfully:
                success_count += 1
            else:
                failed_count += 1
        else:
            failed_count += 1
            errors.append(f"Failed to get IP for LXC {rule['lxc_id']} (Rule ID {rule['id']}). Rule not applied.")

    print(f"Rule application complete. Success: {success_count}, Failed: {failed_count}")
    return success_count, failed_count, errors
