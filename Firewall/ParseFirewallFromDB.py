import sqlite3
from connection_tracking import TrackConnection

class ParseFirewallFromDB:
    def __init__(self, db_file):
        self.db_file = db_file 
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
    def __del__(self):
        self.conn.close()

    def parse(self):
        firewall_dict = {}

        try:
            self.cursor.execute("SELECT src_ip, dst_ip, protocol, src_port, dst_port, state, action FROM firewall_rules")
            rows = self.cursor.fetchall()

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

    def insert_firewall_rules(self, firewall_rules):
        for rule in firewall_rules:
            self.cursor.execute('''
                INSERT INTO firewall_rules (src_ip, dst_ip, protocol, src_port, dst_port, state, action)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', rule)
        self.conn.commit()

    # firewall_rules = [
    #     ("10.0.0.3", "10.0.0.4", "ICMP", None, None, "PING", "DROP"),
    #     ("10.0.0.1", "10.0.0.2", "TCP", 1000, 8080, "NEW", "ALLOW"),
    #     ]
if __name__ == "__main__":
    # db_file = "dataset/firewall-drop.db"
    db_file = "dataset/firewall-vTest.db"
    parser = ParseFirewallFromDB(db_file)
    inner_policy = parser.parse()
    if inner_policy:
        print("Successfully parsed database")
    else: 
        print("Failed to parse database")
    # parser.close_connection()
    # check with code on <here> (if) to see what it queyre
    # check ICMP
    tcp_conn_track = {}
    track = TrackConnection()
    # for src_ip in inner_policy:
    #     temp = inner_policy.get(src_ip)
    #     for i in range(0, len(temp)):
    #         # print(i, " - ip: ", temp[i][0])
    #         xyz = temp[i]
    #         # print(i, " - xyz[1]=",xyz[1], " - xyz[5]=", xyz[5])
    #         icmp_conn_track = track.conn_track_dict(icmp_conn_track,src_ip, temp[i][0], "PING", "PONG", xyz[5],1)
    # for dst in icmp_conn_track:
    #     temp = icmp_conn_track.get(dst)
    #     print("dst_ip: ", dst)
    #     for i in range(0, len(temp)):
    #         print(i, " -ip: ", temp[i][0])
    #         xyz = temp[i]
    #         print("PING - [1]: ", xyz[1], " -- PONG - [2]: ", xyz[2])
    #     print("")
    # Check TCP 
    for src_ip in inner_policy:
        temp = inner_policy.get(src_ip)
        print("srcIP: ", src_ip)
        for i in range(0, len(temp)):
            print(i, " - dstIP: ", temp[i][0], " -- Protocol: ",temp[i][1], " -- srcPort: ", temp[i][2], " -- dstPort: ", temp[i][3])
            xyz = temp[i]
            print(i, " - xyz[1]=",xyz[1], " - xyz[5]=", xyz[5])
            tcp_conn_track = track.conn_track_dict(tcp_conn_track,src_ip, temp[i][0], "PING", "PONG", xyz[5],1)
            print("")
        print("------------------------")
    print("--------------------New-------------")
    for dst_ip in tcp_conn_track:
        temp = tcp_conn_track.get(dst_ip)
        print("")
        print("dstIP: ", dst_ip)
        for i in range(0, len(temp)):
            print(i, " - srcIP: ", temp[i][0], " -- srcPort: ", temp[i][2], " -- dstPort: ", temp[i][1])
            print("")
        print("---------------------")

