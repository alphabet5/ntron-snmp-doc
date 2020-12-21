from pysnmp.hlapi import getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
import traceback

def snmp_get(ip_address, port, community, oid):
    try:
        temp = getCmd(SnmpEngine(), CommunityData(community), UdpTransportTarget((ip_address, port)), ContextData(), ObjectType(ObjectIdentity(oid))).__next__()
        oid, val = temp[3][0]
    except:
        err = traceback.format_exc()
        print(err)
        print('There was an error. Line 6, requesting OID:' + oid + '\tfrom ip address:' + ip_address)
        print(temp)
        val = ''
    return str(val)

def snmp_next(ip_address, port, community, oid):
    return_dict = dict()
    try:
        gen = nextCmd(SnmpEngine(), CommunityData(community), UdpTransportTarget((ip_address, port)), ContextData(), ObjectType(ObjectIdentity(oid)))
        for val in gen:
            o, v = val[3][0]
            if oid.lstrip('.') in str(o):
                return_dict[str(o)] = v
            else:
                break
    except:
        err = traceback.format_exc()
        print(ip,":",oid)
        print(err)
        return_dict = dict()
    return return_dict

def switch_loop(ip):
    with open('community.txt', 'r') as f:
        community_string = f.readline()
    #community_string = 'public'
    sw_dict = dict()
    #Get OID for the N-Tron switch, used to create the future n-tron specific OID for port information
    sw_oid = snmp_get(ip, 161, community_string, '.1.3.6.1.2.1.1.2')
    #Switch number of ports
    num_ports = snmp_get(ip, 161, community_string, '.1.3.6.1.2.1.2.1.0')
    sw_dict['ip'] = ip
    sw_dict['switch_name'] = snmp_get(ip, 161, community_string, '.1.3.6.1.2.1.1.5')
    #sw_dict['switch_model'] = snmp_get(ip, 161, community_string, sw_oid + '.1.17.0')
    #sw_dict['switch_version'] = snmp_get(ip, 161, community_string, sw_oid + '.1.2.0')
    #sw_dict['build_date'] = snmp_get(ip, 161, community_string, sw_oid + '.1.3.0')
    #sw_dict['mac_address'] = snmp_get(ip, 161, community_string, sw_oid + '.1.14.0')
    #Loop through ports to gather information
    interfaces = dict()
    for port_num in range(1, int(num_ports)):
        interface = dict()
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in getCmd(SnmpEngine(),
                                  CommunityData(community_string, mpModel=0),
                                  UdpTransportTarget((ip, 161)),
                                  ContextData(),
                                  ObjectType(ObjectIdentity(sw_oid + '.8.1.1.2.' + str(port_num))),#port name
                                  ObjectType(ObjectIdentity(sw_oid + '.8.1.1.3.' + str(port_num))),#admin status
                                  ObjectType(ObjectIdentity(sw_oid + '.8.1.1.6.' + str(port_num))),#link state
                                  ObjectType(ObjectIdentity(sw_oid + '.8.1.1.4.' + str(port_num))),#port speed
                                  ObjectType(ObjectIdentity(sw_oid + '.8.1.1.5.' + str(port_num))),#port duplex
                                  ObjectType(ObjectIdentity(sw_oid + '.8.1.1.10.' + str(port_num))),#port auto
                                  ObjectType(ObjectIdentity(sw_oid + '.8.1.1.12.' + str(port_num))),#port pvid
                                  ignoreNonIncreasingOid=True,
                                  lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                interface['port_number'] = str(port_num)
                interface['port_name'] = str(varBinds[0][1])
                interface['admin_status'] = 'disabled' if str(varBinds[1][1]) == '1' else 'enabled' if str(varBinds[1][1]) == '2' else 'ERROR'
                interface['link_state'] = 'down' if str(varBinds[2][1]) == '1' else 'up' if str(varBinds[2][1]) == '2' else 'ERROR'
                interface['port_speed'] = 'tempMbps' if str(varBinds[3][1]) == '1' else 'hundredMbps' if str(varBinds[3][1]) == '2' else 'thousandMbps' if str(varBinds[3][1]) == '3' else 'ERROR'
                interface['port_duplex'] = 'half' if str(varBinds[4][1]) == '1' else 'full' if str(varBinds[4][1]) == '2' else 'ERROR'
                interface['port_auto'] = 'enable' if str(varBinds[5][1]) == '2' else 'disable' if str(varBinds[5][1]) == '1' else 'ERROR'
                interface['port_pvid'] = str(varBinds[6][1])
                interface['neighbor'] = ''
            print(interface)
            interfaces[interface['port_name']] = interface

        #interface = dict()
        #interface['port_number'] = str(port_num)
        #SNMP Port name
        #interface['port_name'] = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.2.' + str(port_num))
        #Admin status
        #temp = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.3.' + str(port_num))
        #interface['admin_status'] = 'disabled' if temp == '1' else 'enabled' if temp == '2' else 'ERROR' #INTEGER  { disabled ( 1 ) , enabled ( 2 ) }
        #Link State
        #temp = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.6.' + str(port_num))
        #interface['link_state'] = 'down' if temp == '1' else 'up' if temp == '2' else 'ERROR' #INTEGER  { down ( 1 ) , up ( 2 ) }
        #Port Speed
        #temp = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.4.' + str(port_num))
        #interface['port_speed'] = 'tempMbps' if temp == '1' else 'hundredMbps' if temp == '2' else 'thousandMbps' if temp == '3' else 'ERROR' #INTEGER  { tenMbps ( 1 ) , hundredMbps ( 2 ) , thousandMbps ( 3 ) }
        #Port Duplex
        #temp = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.5.' + str(port_num))
        #interface['port_duplex'] = 'half' if temp == '1' else 'full' if temp == '2' else 'ERROR'  #INTEGER  { half ( 1 ) , full ( 2 ) }
        #Port autonegotiation
        #temp = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.10.' + str(port_num))
        #interface['port_auto'] = 'enable' if temp == '2' else 'disable' if temp == '1' else 'ERROR'  #INTEGER  { enable ( 2 ) , disable ( 1 ) }
        #Port VLAN
        #interface['port_pvid'] = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.12.' + str(port_num)) #INTEGER
        #port folow control
        #temp = snmp_get(ip, 161, community_string, sw_oid + '.8.1.1.8.' + str(port_num))
        #interface['port_flow_control'] = 'disable' if temp == '2' else 'disable' if temp == '1' else 'ERROR' #INTEGER  { enable ( 2 ) , disable ( 1 ) }
        #interfaces[interface['port_number']] = interface
    try:
        mac_address_table = dict()
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in nextCmd(SnmpEngine(),
                                  CommunityData(community_string, mpModel=0),
                                  UdpTransportTarget((ip, 161)),
                                  ContextData(),
                                  ObjectType(ObjectIdentity('.1.3.6.1.2.1.17.4.3.1.1')),
                                  ObjectType(ObjectIdentity('.1.3.6.1.2.1.17.4.3.1.2')),
                                  ignoreNonIncreasingOid=True,
                                  lexicographicMode=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                if str(varBinds[1][1]) not in mac_address_table:
                    mac_address_table[str(varBinds[1][1])] = list()
                mac_address_table[str(varBinds[1][1])].append(str("".join([('00'+hex(x).lstrip('0x'))[-2:] for x in varBinds[0][1]])).upper())
        print(mac_address_table)
        #fetches mac addresses from fdb table. mac addresses are in OctetString format, fixed to 6 hex letter/number format with "".join([hex(x).lstrip('0x') for x in mac_addresses['returned_oid']])
        #mac_addresses = snmp_next(ip, 161, community_string, '.1.3.6.1.2.1.17.4.3.1.1')
        #gets the port number for each oid assigned to the mac addresses
        #mac_ports = snmp_next(ip, 161, community_string, '.1.3.6.1.2.1.17.4.3.1.2')
        #gets a list of the port numbers that exist in the mac address table (removes duplicates)
        #ports = set(port for port in mac_ports.values())
        #creating a dictionary for the mac address table
        #mac_address_table = dict()
        #for port in ports:
        #    mac_address_table[str(port)] = []
        #add the mac addresses to the list of mac addresses for each port on the switch.
        #for key in mac_ports.keys():
        #    try:
        #        mac_address_table[str(mac_ports[key])].append("".join([hex(x).lstrip('0x') for x in mac_addresses[key.replace('1.3.6.1.2.1.17.4.3.1.2', '1.3.6.1.2.1.17.4.3.1.1')]]))
        #    except KeyError:
        #        err = traceback.format_exc()
        #        print(key)
        #        print(err)
    except:
        print("Error processing bridge forwarding table.")
        err = traceback.format_exc()
        print(ip)
        print(err)

    lldp_neighbors = dict()#snmp_next(ip, 161, community_string, '.1.0.8802.1.1.2.1.4.1.1.9')
    #lldp_neighbor_ports = snmp_next(ip, 161, community_string, '.1.0.8802.1.1.2.1.4.1.1.8')
    #lldp_ports = snmp_next(ip, 161, community_string, '.1.0.8802.1.1.2.1.4.1.1.7')
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community_string, mpModel=0),
                              UdpTransportTarget((ip, 161)),
                              ContextData(),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.7')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.8')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.9')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.1')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.2')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.3')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.4')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.5')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.6')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.10')),
                              ObjectType(ObjectIdentity('.1.0.8802.1.1.2.1.4.1.1.11')),
                              ignoreNonIncreasingOid=True,
                              lexicographicMode=False):
        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            oid = str(varBinds[0][0])
            #2nd from last in the oid is the port number eg x.x.x.26.1 means port 26 on the local switch.
            lldp_neighbors[oid[[pos for pos, char in enumerate(oid) if char == '.'][-2] + 1:
                               [pos for pos, char in enumerate(oid) if char == '.'][-1]]] = str(
                varBinds[2][1]) + " - " + str(varBinds[1][1]) + ' - ' + str(varBinds[0][1])

    #add the mac address table for each port to the dictionary containing all switch properties.
    print(lldp_neighbors)
    for int_name in interfaces.keys():#range(len(interfaces)):
        interfaces[int_name]['mac_address_table'] = ""
        for port in mac_address_table.keys():
            if interfaces[int_name]['port_number'] == port:
                interfaces[int_name]['mac_address_table'] = mac_address_table[port]
        try:
            for int_number in lldp_neighbors.keys():
                if interfaces[int_name]['port_number'] == int_number:
                    interfaces[int_name]['neighbor'] = lldp_neighbors[int_number]
                    interfaces[int_name]['mac_address_table'] = ''
        except:
            print("Error processing lldp")
            print(traceback.format_exc())
    sw_dict['interfaces'] = interfaces    
    return sw_dict

if __name__ == '__main__':
    switches = {}
    with open('switch_list.txt', 'r') as f:
        content = f.readlines()
        switch_list = [x.strip() for x in content]
    print(switch_list)
    #p = Pool(32)
    #switch_return_list = list(tqdm(p.imap(switch_loop, switch_list),total=len(switch_list)))
    #for ip in switch_list:
    #    switches[ip] = switch_loop(ip)
    with open('output.txt','w') as output_file:
        #Set column headers
        output_file.write('Switch\tIP\tint\tdevice\tdescription\tline_protocol\tip_address\tneighbor & port\tmode\tmac_address\tvlan\n')
        for ip in switch_list:
            print(ip)
            switches[ip] = switch_loop(ip)
            #Write output to output.txt file
            for i in switches[ip]['interfaces'].keys():
                device_count = 0
                interface = switches[ip]['interfaces'][i]
                if interface['mac_address_table'] == '':
                    interface['mac_address_table'] = ["N/A"]
                for j in interface['mac_address_table']:
                    device_count += 1
                    if j == 'N/A':
                        mac_address = 'N/A'
                    elif len(j) < 12:
                        mac_address = '0'*(12-len(str(j))) + str(j)
                    else:
                        mac_address = str(j)

                    output_file.write(\
                        switches[ip]['switch_name'] + '\t' + \
                        ip + '\t' + \
                        #switches[ip]['switch_model'] + '\t' + \
                        #switches[ip]['switch_version'] + '\t' + \
                        #switches[ip]['build_date'] + '\t' + \
                        #switches[ip]['mac_address'] + '\t' + \
                        #i['port_number'] + '\t' + \
                        interface['port_name'] + '\t' + \
                        str(device_count) + '\t' + \
                        '' + '\t' + \
                        #no descriptions on interfaces
                        interface['admin_status'] + '/' + \
                        interface['link_state'] + '\t' + \
                        '' + '\t' + \
                        #no layer 3 for ip address
                        interface['neighbor'] + '\t' + \
                        interface['port_speed'] + '/' + \
                        interface['port_duplex'] + '/' + \
                        interface['port_auto'] + '\t' + \
                        #i['port_flow_control'] + '\t' + \
                        mac_address + '\t' + \
                        interface['port_pvid'] + '\r\n')
                #",".join(i['mac_address_table']) + '\n')

                #snmp_next('192.168.199.44', 161, 'cybertrol', '.1.0.8802.1.1.2.1.4.1.1.9').values()
