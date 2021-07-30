#!/usr/bin/python
import os, sys, time, random, shutil

def create_mac(switch):
	if switch <= 99:
		if (switch < 10):
			return "01:00:00:00:00:0"+str(switch) 
		else:
			return "01:00:00:00:00:"+str(switch)
	else:
		aux = int(switch/100)
		aux2 = int(switch % 100)
		if aux < 10:
			if (aux2 < 10):
				return "01:00:00:00:0"+str(aux)+":0"+str(switch)
			else:
				return "01:00:00:00:0"+str(aux)+":"+str(switch)
		else:
			if (aux2 < 10):
				return "01:00:00:00:"+str(aux)+":0"+str(switch)
			else:
				return "01:00:00:00:"+str(aux)+":"+str(switch)


if __name__ == '__main__':

	if sys.argv[1] == "-h":
		help()
		exit;
    
	number_switches = int(sys.argv[1])
	number_interfaces = int(sys.argv[2])
	path = str(sys.argv[3])

	if int(number_switches) > 0:
		for switch in range(1, number_switches+1):
			file_name = path + "/s"+str(switch)+"-runtime.json"
			print ("Creando fichero: "+str(file_name)+"\n")
			msg = '{"target":"bmv2", "p4info":"build/hddp_t.p4.p4info.txt", "bmv2_json": "build/hddp_t.json", "table_entries": ['
			msg +='{"table":"MyIngress.mac_table_1","match": { "1": [1] }, "action_name": "MyIngress.set_mac", "action_params":{ "nodeAddr":"'+str(create_mac(switch))+'"}},'
    			msg +='{"table":"MyIngress.mac_table_2","match": { "1": [1] }, "action_name": "MyIngress.set_mac", "action_params":{ "nodeAddr":"'+str(create_mac(switch))+'"}}],'
			msg +='"multicast_group_entries" : [ { "multicast_group_id" : 1, "replicas" : ['
			for i in range(0, number_interfaces):
				msg +='{ "egress_port" : '+str(i+1)+', "instance" : 1 }'
				if ( i+1 <number_interfaces ):
					msg +=','
			msg +=' ] } ] } '
			f=open(file_name,"w")
			f.write(msg)
			f.close()
