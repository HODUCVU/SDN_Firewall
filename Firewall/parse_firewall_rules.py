import copy

class parse_firewall:
    
    
    def parse(self):
        firewall_file = open("firewall.txt")
        list1 = []
        firewall_dict = {}
        listobj = []
        
        lines = [line.strip() for line in firewall_file]
        for i in range(len(lines)):
            
            list1.append(lines[i].split(',')) 
            list2 = copy.deepcopy(list1)
            if((list2[i][0])) not in firewall_dict:
                key = str(list2[i][0])
                list2[i].remove(key)
                tup = tuple(list2[i])
                listobj.append(tup)
                tup = tuple(listobj)
                firewall_dict[key] = tup
                
            elif ((list2[i][0])) in firewall_dict:
                key = str(list2[i][0])
                dst = firewall_dict[key]
                dst = list(dst)
                list2[i].remove(key)
                dst.append(tuple(list2[i]))
                tup = tuple(dst)
                firewall_dict[key] = tup
                
            del listobj[:] 
        print(len(firewall_dict.keys()))
        return firewall_dict
