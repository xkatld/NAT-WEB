import sqlite3
import os
from flask import g

DATABASE = 'nat_rules.db'

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = dict_factory
    return db

def close_db(e=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
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
            UNIQUE(external_ip, external_port, protocol)
        )
    ''')
    db.commit()
    print("数据库初始化完成。")

def get_all_rules():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM rules ORDER BY lxc_id, external_port")
    return cursor.fetchall()

def get_rule(rule_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM rules WHERE id = ?", (rule_id,))
    return cursor.fetchone()

def add_rule(description, lxc_id, container_port, external_port, protocol, external_ip='0.0.0.0', enabled=True):
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
        print("错误：外部映射（IP、端口、协议）已存在。")
        return None
    except Exception as e:
        print(f"数据库添加规则时出错：{e}")
        return None


def update_rule(rule_id, description, lxc_id, container_port, external_port, protocol, external_ip='0.0.0.0', enabled=True):
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
        print("错误：外部映射（IP、端口、协议）已存在。")
        return False
    except Exception as e:
        print(f"数据库更新规则 {rule_id} 时出错：{e}")
        return False

def delete_rule(rule_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    db.commit()
    return True

def toggle_rule_enabled(rule_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE rules SET enabled = NOT enabled WHERE id = ?", (rule_id,))
    db.commit()
    cursor.execute("SELECT enabled FROM rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    return row['enabled'] if row else None
