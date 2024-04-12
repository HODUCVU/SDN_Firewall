# Problem
* Tai sao chon topic Firewall
* Uu/nhuoc Firewall tranditional and SDN
# Solve
* Cac hinh thuc tinh cong: DoS, DDoS, **Scan port**,...
* Firewall dap ung dc uu diem cua SDN nhu the nao.
* Firewall co nhung dac diem nao, chuc nang nao, uu diem cua no so voi Firewall tranditional.
* Tim ra tat ca cac rules cho firewall va deploy cac truong hop do.
* Su dung protocols nao: IP -> IPv4/IPv6, TCP/IP, UDP, ICMP
* Tai sao lai block host do, block nhung cai gi tu host do gui den switch.
* kiem tra tinh bat thuong cua cac flows. Nhu s\_ip khac nhau nhung cung 1 dst\_ip
* kiem tra payload, neu cac packages ko co payload thi package do co tiem nang la tan cong den   host/switch.
* Khong chan 'tat ca -> toi uu' cac package tu mot ip address, ma la lua chon cac package nao bi drop tu ip do, kieu nhu toi uu.
* Run real-time
### Steps
```
 1. Thu thap thong tin nao cua packages va thu thap nhu the nao.
```
# Result
# Conclusion
* Khong lien quan: tracking package's payload use 'deep package inspection' and use AI for it

