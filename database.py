import sqlite3
import os

DATABASE = 'nat_rules.db'

def dict_factory(cursor, row):
    """Helper function to return database rows as dictionaries."""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
    """Connect to the SQLite database."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = dict_factory # Use dictionary factory
    return db

def close_db(e=None):
    """Close the database connection."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Create the database tables if they don't exist."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT NOT NULL,
            lxc_id INTEGER NOT NULL,
            container_port INTEGER NOT NULL,
            external_port INTEGER NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp', 'both')),
            external_ip TEXT DEFAULT '0.0.0.0',
            enabled BOOLEAN DEFAULT 1,
            UNIQUE(external_ip, external_port, protocol) -- Prevent duplicate external mappings
        )
    ''')
    db.commit()
    print("Database initialized.")

def get_all_rules():
    """Fetch all NAT rules from the database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM rules ORDER BY lxc_id, external_port")
    return cursor.fetchall()

def get_rule(rule_id):
    """Fetch a single rule by ID."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM rules WHERE id = ?", (rule_id,))
    return cursor.fetchone()

def add_rule(description, lxc_id, container_port, external_port, protocol, external_ip='0.0.0.0', enabled=True):
    """Add a new rule to the database."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('''
            INSERT INTO rules (description, lxc_id, container_port, external_port, protocol, external_ip, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (description, lxc_id, container_port, external_port, protocol, external_ip, enabled))
        db.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        print("Error: Duplicate external mapping (IP, Port, Protocol) exists.")
        return None
    except Exception as e:
        print(f"Database error adding rule: {e}")
        return None


def update_rule(rule_id, description, lxc_id, container_port, external_port, protocol, external_ip='0.0.0.0', enabled=True):
    """Update an existing rule in the database."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('''
            UPDATE rules SET
                description = ?,
                lxc_id = ?,
                container_port = ?,
                external_port = ?,
                protocol = ?,
                external_ip = ?,
                enabled = ?
            WHERE id = ?
        ''', (description, lxc_id, container_port, external_port, protocol, external_ip, enabled, rule_id))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        print("Error: Duplicate external mapping (IP, Port, Protocol) exists.")
        return False
    except Exception as e:
        print(f"Database error updating rule {rule_id}: {e}")
        return False

def delete_rule(rule_id):
    """Delete a rule from the database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    db.commit()
    return True

def toggle_rule_enabled(rule_id):
    """Toggle the 'enabled' status of a rule."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE rules SET enabled = NOT enabled WHERE id = ?", (rule_id,))
    db.commit()
    # Get the new status
    cursor.execute("SELECT enabled FROM rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    return row['enabled'] if row else None

# Import g from flask for context
from flask import g
