# -*- coding: utf-8 -*-

from setting import get_hosts, get_switches, get_links, get_ip, get_mac

class packet:
    def __init__(self, type):
        self.type = type    # property
        self._rtype = None
        self._src_mac = None
        self._dst_mac = None
        self._src_ip = None
        self._dst_ip = None
    @property
    def type(self):
        try:
            return self._type
        except AttributeError:
            return None
    @type.setter
    def type(self, type):
        if type == "arp" or type == "icmp":
            self._type = type
        else:
            print("Invalid packet type (arp/icmp)")
    @property
    def rtype(self):
        try:
            return self._rtype
        except AttributeError:
            return None
    @rtype.setter
    def rtype(self, rtype):
        if rtype == "req" or rtype == "resp":
            self._rtype = rtype
        else:
            print("Invalid rtype (req/resp)")
    def get_mac(self):
        return (self._src_mac, self._dst_mac)
    def set_mac(self, src, dst):
        self._src_mac = src
        self._dst_mac = dst
    def get_ip(self):
        return (self._src_ip, self._dst_ip)
    def set_ip(self, src, dst):
        self._src_ip = src
        self._dst_ip = dst

class host:
    def __init__(self, name, ip, mac):
        self.name = name
        self.ip = ip
        self.mac = mac 
        self.port_to = None 
        self.arp_table = dict() # maps IP addresses to MAC addresses
    def add(self, node):
        self.port_to = node
    def show_table(self):
        for i in self.arp_table:
            print(f'{i} : {self.arp_table[i]}')
    def clear(self):
        # clear ARP table entries for this host
        self.arp_table.clear()
    def update_arp(self, ip, mac):
        # update ARP table with a new entry
        self.arp_table[ip] = mac
    def ping(self, dst_ip):  
        # handle a ping request
        if dst_ip not in self.arp_table:
            pkt = packet("arp")
            pkt.rtype = "req"
            pkt.set_mac(self.mac, "ffff")
            pkt.set_ip(self.ip, dst_ip)
        else:
            pkt = packet("icmp")
            pkt.rtype = "req"
            pkt.set_mac(self.mac, self.arp_table[dst_ip])
            pkt.set_ip(self.ip, dst_ip)
        self.send(pkt)
    def send(self, pkt: packet):
        # determine the destination MAC here
        '''
            Hint :
                if the packet is the type of arp request, destination MAC would be 'ffff'.
                else, check up the arp table.
        '''
        node = self.port_to # get node connected to this host
        node.handle_packet(pkt, self) # send packet to the connected node
    def handle_packet(self, pkt: packet, node):
        # print("TRACE:", self.name, pkt.type, pkt.rtype)
        # handle incoming packets
        mac = pkt.get_mac()
        ip = pkt.get_ip()
        # drop pkt if src == dst
        if mac[0] == mac[1]:
            return
        # drop pkt if not self
        if ip[1] != self.ip:
            return
        # handle arp
        if pkt.type == "arp":
            # update arp_table
            self.update_arp(ip[0], mac[0])
            # arp response
            if mac[1] == "ffff":
                resp = packet("arp")
                resp.rtype = "resp"
                resp.set_mac(self.mac, mac[0])
                resp.set_ip(self.ip, ip[0])
                self.send(resp)
                return
            # icmp request
            self.ping(ip[0])
        # icmp response
        elif pkt.rtype == "req":
            resp = packet("icmp")
            resp.rtype = "resp"
            resp.set_mac(self.mac, mac[0])
            resp.set_ip(self.ip, ip[0])
            self.send(resp)

class switch:
    def __init__(self, name, port_n):
        self.name = name
        self.mac_table = dict() # maps MAC addresses to port numbers
        self.port_n = port_n # number of ports on this switch
        self.port_to = list() 
    def add(self, node): # link with other hosts or switches
        self.port_to.append(node)
    def show_table(self):
        for m in self.mac_table:
            print(f'{m} : {self.mac_table[m]}')
    def clear(self):
        # clear MAC table entries for this switch
        self.mac_table.clear()
    def update_mac(self, mac, port):
        # update MAC table with a new entry
        self.mac_table[mac] = port
    def send(self, idx, pkt: packet): # send to the specified port
        node = self.port_to[idx] 
        node.handle_packet(pkt, self) 
    def handle_packet(self, pkt: packet, node):
        # print("TRACE:", self.name, pkt.type, pkt.rtype)
        # handle incoming packets
        mac = pkt.get_mac()
        # drop pkt if src == dst
        if mac[0] == mac[1]:
            return
        # update mac table
        i_port = self.port_to.index(node)
        self.update_mac(mac[0], i_port)
        # flood
        if mac[1] == "ffff" or mac[1] not in self.mac_table:
            for i in range(self.port_n):
                # avoid return to sender
                if i == i_port:
                    continue
                self.send(i, pkt)
            return
        else:
            # avoid return to sender
            o_port = self.mac_table[mac[1]]
            if o_port != i_port:
                self.send(self.mac_table[mac[1]], pkt)

def add_link(tmp1, tmp2): # create a link between two nodes
    if tmp1 in host_dict:
        node1 = host_dict[tmp1]
    else:
        node1 =  switch_dict[tmp1]
    if tmp2 in host_dict:
        node2 = host_dict[tmp2]
    else:
        node2 = switch_dict[tmp2]
    node1.add(node2)

def set_topology():
    global host_dict, switch_dict
    hostlist = get_hosts().split(' ')
    switchlist = get_switches().split(' ')
    link_command = get_links()
    ip_dic = get_ip()
    mac_dic = get_mac()
    
    host_dict = dict() # maps host names to host objects
    switch_dict = dict() # maps switch names to switch objects
    
    for h in hostlist:
        host_dict[h] = host(h, ip_dic[h], mac_dic[h])
    for s in switchlist:
        switch_dict[s] = switch(s, len(link_command.split(s))-1)
    for l in link_command.split(' '):
        [n0, n1] = l.split(',')
        add_link(n0, n1)
        add_link(n1, n0)

def ping(tmp1, tmp2): # initiate a ping between two hosts
    global host_dict, switch_dict
    if tmp1 in host_dict and tmp2 in host_dict : 
        node1 = host_dict[tmp1]
        node2 = host_dict[tmp2]
        node1.ping(node2.ip)
    else : 
        return 1 # wrong 
    return 0 # success 


def show_table(tmp): # display the ARP or MAC table of a node
    if tmp == 'all_hosts':
        print(f'ip : mac')
        for h in host_dict:
            print(f'---------------{h}:')
            host_dict[h].show_table()
        print()
    elif tmp == 'all_switches':
        print(f'mac : port')
        for s in switch_dict:
            print(f'---------------{s}:')
            switch_dict[s].show_table()
        print()
    elif tmp in host_dict:
        print(f'ip : mac\n---------------{tmp}')
        host_dict[tmp].show_table()
    elif tmp in switch_dict:
        print(f'mac : port\n---------------{tmp}')
        switch_dict[tmp].show_table()
    else:
        return 1
    return 0


def clear(tmp):
    wrong = 0
    if tmp in host_dict:
        host_dict[tmp].clear()
    elif tmp in switch_dict:
        switch_dict[tmp].clear()
    else:
        wrong = 1
    return wrong


def run_net():
    while(1):
        wrong = 0 
        command_line = input(">> ")
        command_list = command_line.strip().split(' ')
        
        if command_line.strip() =='exit':
            return 0
        if len(command_list) == 2 : 
            if command_list[0] == 'show_table':
                wrong = show_table(command_list[1])
            elif command_list[0] == 'clear' :
                wrong = clear(command_list[1])
            else :
                wrong = 1 
        elif len(command_list) == 3 and command_list[1] == 'ping' :
            wrong = ping(command_list[0], command_list[2])
        else : 
            wrong = 1
        if wrong == 1:
            print('a wrong command')

    
def main():
    set_topology()
    run_net()


if __name__ == '__main__':
    main()