import sqlite3

class ParseFirewall:
    
    def parse(self):
        # Connect to the SQLite database
        conn = sqlite3.connect('firewallDB.db')
        cursor = conn.cursor()
        
        # Read firewall rules from the database
        cursor.execute("SELECT * FROM firewall_rules")
        firewall_rules = cursor.fetchall()
        
        # Close the database connection
        conn.close()
        
        # Process the firewall rules as needed
        firewall_dict = {}
        for rule in firewall_rules:
            src_ip, dst_ip, protocol, src_port, dst_port, state, action = rule
            if src_ip not in firewall_dict:
                firewall_dict[src_ip] = []
            firewall_dict[src_ip].append((dst_ip, protocol, src_port, dst_port, state, action))
        
        return firewall_dict

if __name__ == "__main__":
    parser = ParseFirewall()
    firewall_rules = parser.parse()
    print(firewall_rules)
