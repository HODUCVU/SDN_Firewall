
import sqlite3

class FirewallManager:
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                state TEXT,
                action TEXT
            )
        ''')
        self.conn.commit()

    def insert_firewall_rules(self, firewall_rules):
        for rule in firewall_rules:
            self.cursor.execute('''
                INSERT INTO firewall_rules (src_ip, dst_ip, protocol, src_port, dst_port, state, action)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', rule)
        self.conn.commit()

    def close_connection(self):
        self.conn.close()

if __name__ == "__main__":
    db_file = "firewall.db"
    firewall_rules = [
        ("10.0.0.1", "10.0.0.2", "TCP", 1000, 8080, "NEW", "ALLOW"),
        ("10.0.0.1", "10.0.0.3", "TCP", 1000, 8080, "NEW", "ALLOW"),
        ("10.0.0.2", "10.0.0.3", "TCP", 1000, 1000, "NEW", "ALLOW"),
    ]

    firewall_manager = FirewallManager(db_file)
    firewall_manager.create_table()
    firewall_manager.insert_firewall_rules(firewall_rules)
    firewall_manager.close_connection()
