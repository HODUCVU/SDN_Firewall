import sqlite3

class ParseFirewallFromDB:
    def __init__(self, db_file):
        self.db_file = db_file 
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()

    def parse(self):
        firewall_dict = {}

        try:
            self.cursor.execute("SELECT src_ip, dst_ip, protocol, src_port, dst_port, state, action FROM firewall_rules")
            rows = self.cursor.fetchall()

            # In ra thông tin từ các hàng trong bảng
            print("Firewall Rules:")
            print("Source IP | Destination IP | Protocol | Source Port | Destination Port | State | Action")
            for row in rows:
                src_ip, dst_ip, protocol, src_port, dst_port, state, action = row 
                print(f"{src_ip} | {dst_ip} | {protocol} | {src_port} | {dst_port} | {state} | {action}")
                key = str(src_ip)
                value = (dst_ip, protocol, src_port, dst_port, state, action)

                if key not in firewall_dict:
                    firewall_dict[key] = [value]
                else: 
                    firewall_dict[key].append(value)
            # self.conn.close()
            return firewall_dict
        except sqlite3.Error as e:
            print("Error in parse database: ", e)
            return {}

    def close_connection(self):
        self.conn.close()

if __name__ == "__main__":
    db_file = "firewall-vTest.db"
    parser = ParseFirewallFromDB(db_file)
    inner_policy = parser.parse()
    if inner_policy:
        print("Successfully parsed database")
    else: 
        print("Failed to parse database")
    parser.close_connection()
    # print("SQLite version: ",sqlite3.version, " -> sqlite3.version")
    # print("Lib version sqlite3: ", sqlite3.sqlite_version, " -> sqlite3.sqlite_version")

