# firewall.py

import subprocess
import sys
import time

# Define the custom iptables chain managed by this app
NAT_CHAIN = "PVE_LXC_NAT"
# A comment to identify rules managed by this app
RULE_COMMENT_PREFIX = "pvelxcnat:"

def _run_command(cmd):
    """Helper to run shell commands safely, returning stdout on success or None on error."""
    print(f"Executing command: {' '.join(cmd)}")
    try:
        # Use check=True to raise CalledProcessError on non-zero exit codes
        # text=True ensures stdout/stderr are strings IF the command completes successfully
        # Added timeout to prevent hanging commands
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        # print("STDOUT:", result.stdout.strip()) # Uncomment for verbose debugging
        # print("STDERR:", result.stderr.strip()) # Uncomment for verbose debugging
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"Error: Command not found. Make sure iptables, pct, and sudo are installed and in the PATH.", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}", file=sys.stderr)
        # Print stdout/stderr (already strings due to text=True)
        print("STDOUT:", e.stdout.strip(), file=sys.stderr)
        print("STDERR:", e.stderr.strip(), file=sys.stderr)

        # Specific error check for iptables chain already exists/does not exist
        # Use string literals for comparison because text=True is used
        # Added checks for non-empty stderr to avoid errors if stderr is empty
        if e.stderr and "Chain already exists" in e.stderr:
            print("Info: iptables chain already exists.")
            # Note: _run_command returning None still indicates the *command* failed (exit code != 0)
            # The caller (_ensure_nat_chain) needs to handle this specific failure gracefully.
        elif e.stderr and "No chain/target/match by that name" in e.stderr:
             print("Info: iptables chain does not exist.")
             # This message for "iptables -S PREROUTING" is unusual and might indicate
             # issues with the iptables/nftables setup on the host.
             # The code proceeds, but subsequent iptables commands might also fail.

        return None # Indicate failure
    except subprocess.TimeoutExpired:
        print(f"Error: Command timed out.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

def _ensure_nat_chain():
    """Ensure the custom NAT chain and jump rule exist."""
    print(f"Ensuring iptables chain '{NAT_CHAIN}' exists...")

    # Attempt to create the chain. Use subprocess.run directly for specific error handling.
    create_cmd = ["sudo", "iptables", "-N", NAT_CHAIN]
    print(f"Attempting to create chain: {' '.join(create_cmd)}")
    try:
        # Use text=True here as well for consistency, check=True to raise on error
        subprocess.run(create_cmd, capture_output=True, text=True, check=True, timeout=5)
        print(f"Chain '{NAT_CHAIN}' created successfully.")
    except subprocess.CalledProcessError as e:
        # Check if the error is because the chain already exists
        # Use string literal because text=True
        if e.stderr and "Chain already exists" in e.stderr:
            print(f"Info: iptables chain '{NAT_CHAIN}' already exists.")
        else:
            # Other errors are problematic
            print(f"Error creating chain '{NAT_CHAIN}' (exit code {e.returncode}): {e.stderr.strip()}", file=sys.stderr)
            # Cannot proceed without the custom chain, exit or raise
            sys.exit(1)
    except FileNotFoundError:
        print(f"Error: iptables command not found.", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"Error: Timeout creating chain.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while creating chain: {e}", file=sys.stderr)
        sys.exit(1)


    print(f"Checking for jump rule from PREROUTING to {NAT_CHAIN}...")
    # List PREROUTING rules to check for the jump rule. Use _run_command for this.
    list_cmd = ["sudo", "iptables", "-S", "PREROUTING"]
    existing_rules_output = _run_command(list_cmd) # This returns string or None

    jump_rule_spec = f"-A PREROUTING -j {NAT_CHAIN}"

    if existing_rules_output is None:
         print("Error retrieving existing PREROUTING rules. Cannot verify/add jump rule. Firewall sync may be incomplete.", file=sys.stderr)
         # Do not return/exit here, allow subsequent rule application attempts even if jump is missing
         # which might reveal other iptables issues or apply rules that are already jumped to.
    elif jump_rule_spec not in existing_rules_output.splitlines():
        print(f"Adding jump rule to {NAT_CHAIN} from PREROUTING...")
        # Add the jump rule to PREROUTING at the beginning (-I 1)
        # Using -I 1 is generally better to ensure it's checked early
        add_jump_cmd = ["sudo", "iptables", "-I", "PREROUTING", "-j", NAT_CHAIN]
        if _run_command(add_jump_cmd) is None:
             print(f"Error adding jump rule: {' '.join(add_jump_cmd)}", file=sys.stderr)
             print("Firewall sync may be incomplete.", file=sys.stderr)
        else:
             print("Jump rule added successfully.")
    else:
        print("Jump rule already exists.")


def _clear_nat_chain():
    """Flush all rules from the custom NAT chain."""
    print(f"Flushing rules in chain '{NAT_CHAIN}'...")
    # Use -F to flush. This should work even if the chain is empty.
    # If the chain doesn't exist, -F will fail. We assume _ensure_nat_chain ran first.
    flush_cmd = ["sudo", "iptables", "-F", NAT_CHAIN]
    if _run_command(flush_cmd) is None:
         print(f"Error flushing chain '{NAT_CHAIN}': {' '.join(flush_cmd)}", file=sys.stderr)
         print("Existing NAT rules may not have been removed.", file=sys.stderr)
    else:
        print(f"Chain '{NAT_CHAIN}' flushed.")


def _get_lxc_ip(lxc_id):
    """Get the current IP address of an LXC container using pct exec."""
    print(f"Getting IP for LXC {lxc_id}...")
    # Command to get the first IPv4 address on eth0
    # Requires root/sudo to run pct exec
    # Use -brief to get just the IP if possible, fallback to parsing if needed
    cmd = ["sudo", "pct", "exec", str(lxc_id), "--", "ip", "-4", "-brief", "addr", "show", "eth0"]
    output = _run_command(cmd)

    if output:
        # The -brief output is simpler: "eth0  UNKNOWN/UP  <IP>/<MASK>"
        parts = output.split()
        if len(parts) >= 3 and 'inet' not in parts: # Check for brief output format
             try:
                ip_with_mask = parts[2]
                ip = ip_with_mask.split('/')[0]
                print(f"Found IP: {ip} for LXC {lxc_id} (brief output).")
                return ip
             except (ValueError, IndexError):
                 print(f"Could not parse brief IP line: {output}", file=sys.stderr)
                 # Fallback to parsing full output if brief failed? Or just fail. Let's fail for now.
                 return None
        else: # Fallback to parsing full output if brief didn't work or failed
             print(f"Attempting to parse full ip addr output for LXC {lxc_id}...")
             cmd_full = ["sudo", "pct", "exec", str(lxc_id), "--", "ip", "-4", "addr", "show", "eth0"]
             output_full = _run_command(cmd_full)
             if output_full:
                 for line in output_full.splitlines():
                     if ' inet ' in line:
                         parts = line.split()
                         try:
                            inet_index = parts.index('inet')
                            ip_with_mask = parts[inet_index + 1]
                            ip = ip_with_mask.split('/')[0]
                            print(f"Found IP: {ip} for LXC {lxc_id} (full output parse).")
                            return ip
                         except (ValueError, IndexError):
                            print(f"Could not parse full IP line: {line}", file=sys.stderr)
                 print(f"No IPv4 address found on eth0 for LXC {lxc_id}.", file=sys.stderr)
             else:
                 print(f"Failed to get full network info for LXC {lxc_id}.", file=sys.stderr)


    print(f"Failed to get IP for LXC {lxc_id}.", file=sys.stderr)
    return None # IP not found or error


def _build_iptables_rule_cmd(rule, container_ip):
    """Build the iptables command list for a single rule."""
    # iptables -A PVE_LXC_NAT -d <external_ip> -p <protocol> --dport <external_port> -j DNAT --to-destination <container_ip>:<container_port> -m comment --comment "pvelxcnat:<rule_id>"

    base_cmd = [
        "sudo", "iptables", "-A", NAT_CHAIN,
        "-d", rule['external_ip'],
        "--dport", str(rule['external_port']),
        "-j", "DNAT",
        "--to-destination", f"{container_ip}:{rule['container_port']}",
        "-m", "comment", "--comment", f"{RULE_COMMENT_PREFIX}{rule['id']}"
    ]

    commands = []
    protocol = rule['protocol'].lower()

    if protocol == 'tcp' or protocol == 'both':
        cmd_tcp = base_cmd[:] # Copy the base command
        cmd_tcp.insert(cmd_tcp.index("--dport"), "-p") # Insert protocol before dport
        cmd_tcp.insert(cmd_tcp.index("-p") + 1, "tcp")
        commands.append(cmd_tcp)

    if protocol == 'udp' or protocol == 'both':
        cmd_udp = base_cmd[:] # Copy the base command
        cmd_udp.insert(cmd_udp.index("--dport"), "-p") # Insert protocol before dport
        cmd_udp.insert(cmd_udp.index("-p") + 1, "udp")
        commands.append(cmd_udp)

    return commands # Return a list of commands (1 or 2)


def apply_all_rules(rules_from_db):
    """
    Apply all enabled rules from the database to the firewall.
    This clears the custom chain and re-addses all enabled rules.
    """
    print("\n--- Applying all enabled rules ---")
    # Ensure chain exists and jump rule is in place first
    _ensure_nat_chain()
    # Then clear existing rules from our managed chain
    _clear_nat_chain()

    success_count = 0
    failed_count = 0
    errors = []

    # Process enabled rules
    enabled_rules = [rule for rule in rules_from_db if rule['enabled']]

    if not enabled_rules:
        print("No enabled rules to apply.")
        print("--- Rule application finished ---\n")
        return 0, 0, [] # success, failed, errors

    print(f"Found {len(enabled_rules)} enabled rules to apply.")

    for rule in enabled_rules:
        print(f"Applying rule ID {rule['id']} (LXC {rule['lxc_id']} ext:{rule['external_port']}/{rule['protocol']} -> cont:{rule['container_port']})...")
        container_ip = _get_lxc_ip(rule['lxc_id'])

        if container_ip:
            commands = _build_iptables_rule_cmd(rule, container_ip)
            applied_successfully = True
            if not commands:
                applied_successfully = False
                errors.append(f"Failed to build command for rule ID {rule['id']} (protocol error?).")
            else:
                for cmd in commands:
                    if _run_command(cmd) is None:
                        applied_successfully = False
                        errors.append(f"Failed to apply rule ID {rule['id']} command: {' '.join(cmd)}")
                        # If one command fails (e.g., TCP), the other (UDP) might still succeed.
                        # We count it as a failed *rule* application if any command fails.
                        break # Stop applying commands for this rule if one fails
            if applied_successfully:
                success_count += 1
            else:
                failed_count += 1
        else:
            failed_count += 1
            errors.append(f"Failed to get IP for LXC {rule['lxc_id']} (Rule ID {rule['id']}). Rule not applied.")
        print("-" * 20) # Separator for each rule application attempt

    print(f"--- Rule application complete. Success: {success_count}, Failed: {failed_count} ---\n")
    return success_count, failed_count, errors
