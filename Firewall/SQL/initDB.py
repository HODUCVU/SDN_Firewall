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

    def insert_firewall_rules_from_file(self, file_path):
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.strip().split(',')
                if len(parts) != 7:
                    continue
                src_ip = parts[0]
                dst_ip = parts[1]
                protocol = parts[2]
                src_port = int(parts[3]) if parts[3].isdigit() else None 
                dst_port = int(parts[4]) if parts[4].isdigit() else None 
                state = parts[5] if parts[5] != '-' else None 
                action = parts[6]

                # Insert into database
                self.cursor.execute('''
                    INSERT INTO firewall_rules (src_ip, dst_ip, protocol, src_port, dst_port, state, action)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (src_ip, dst_ip, protocol, src_port, dst_port, state, action))
        self.conn.commit()


    def close_connection(self):
        self.conn.close()

def readFiletoDatabase(db_file, file_path):
    firewall_manager = FirewallManager(db_file)
    firewall_manager.create_table()
    firewall_manager.insert_firewall_rules_from_file(file_path)
    firewall_manager.close_connection()

if __name__ == "__main__":
    db_file = "dataset/firewall-drop.db"
    # readFiletoDatabase(db_file, "SQL/firewallDrop.csv")
    firewall_rules = [
        ("10.0.0.1", "10.0.0.14", "ICMP", None, None, "PING", "DROP"),
        # ("10.0.0.3", "10.0.0.4", "ICMP", None, None, "PING", "DROP"),
        # ("10.0.0.2", "10.0.0.1", "ICMP", None, None, "PING", "ALLOW")
        # ("10.0.0.1", "10.0.0.2", "TCP", 1000, 8080, "NEW", "ALLOW"),
        # ("10.0.0.1", "10.0.0.3", "TCP", 1000, 8080, "NEW", "ALLOW"),
        # ("10.0.0.2", "10.0.0.3", "TCP", 1000, 1000, "NEW", "ALLOW"),
        # ("10.0.0.2", "10.0.0.1", "TCP", 8080, 1000, "EST", "ALLOW"),
        # ("10.0.0.2", "10.0.0.3", "TCP", 1000, 1000, "EST", "ALLOW"),
        # ("10.0.0.3", "10.0.0.2", "TCP", 1000, 1000, "EST", "ALLOW"),
        # ("10.0.0.3", "10.0.0.2", "TCP", 1000, 1000, "NEW", "ALLOW"),
        # ("10.0.0.3", "10.0.0.1", "TCP", 8080, 1000, "EST", "ALLOW"),
        # ("10.0.0.1", "10.0.0.2", "UDP", 1000, 8080, None,"ALLOW"),
        # ("10.0.0.1", "10.0.0.3", "UDP", 1000, 8080, None, "ALLOW"),
        # ("10.0.0.3", "10.0.0.1", "UDP", 8080, 1000, None, "ALLOW"),
        # ("10.0.0.3", "10.0.0.2", "UDP", 1000, 1000, None, "ALLOW"),
        # ("10.0.0.2", "10.0.0.1", "UDP", 8080, 1000, None, "ALLOW"),
        # ("10.0.0.2", "10.0.0.3", "UDP", 1000, 8080, None, "ALLOW"),
        # ("10.0.0.1", "10.0.0.2", "ICMP", None, None, "PING", "ALLOW"),
        # ("81.84.126.220", "147.83.42.206", "UDP", 57253, 1897, None, "ALLOW"),
        # ("81.84.126.220", "147.83.42.206", "TCP", 57253, 1897, "NEW", "ALLOW"),
    ]
    firewall_manager = FirewallManager(db_file)
    firewall_manager.create_table()
    firewall_manager.insert_firewall_rules(firewall_rules)
    firewall_manager.close_connection()
