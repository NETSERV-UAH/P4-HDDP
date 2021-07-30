#!/usr/bin/python
import os, sys, time, random, shutil

def create_mac(switch):
	if switch <= 99:
		if (switch < 10):
			return "11:11:00:00:00:0"+str(switch) 
		else:
			return "11:11:00:00:00:"+str(switch)
	else:
		aux = int(switch/100)
		aux2 = int(switch % 100)
		if aux < 10:
			if (aux2 < 10):
				return "11:11:00:00:0"+str(aux)+":0"+str(switch)
			else:
				return "11:11:00:00:"+str(aux)+":"+str(switch)
		else:
			if (aux2 < 10):
				return "11:11:00:00:0"+str(aux)+":0"+str(switch)
			else:
				return "11:11:00:00:"+str(aux)+":"+str(switch)


if __name__ == '__main__':

	if sys.argv[1] == "-h":
		help()
		exit;
    
	path = str(sys.argv[1])	
	topology_type = str(sys.argv[2])
	degree = int(sys.argv[3])	
	seed = int(sys.argv[4])
	num_nodes = int(sys.argv[5])
	number_sdn = int(sys.argv[6])
	num_sdn_topology = 0
	num_no_sdn_topo = 0
	
	#create switch p4 json
	os.system("python create_switches_runtime.py "+str(num_nodes)+" "+str(num_nodes)+" .")

	msg = '{ "hosts": { }, \n'
	#insert nodes
	names = []
	msg += '"switches": { \n'
	for node in range (0, num_nodes):
		if (random.randint(0, num_nodes) <= int(num_nodes/2) and num_sdn_topology < number_sdn) or (num_nodes - num_no_sdn_topo == number_sdn - num_sdn_topology):
			msg += '"OvS'+str(node+1)+'": { "switch_class" : "OVSSwitch" }'
			num_sdn_topology = int(num_sdn_topology) + 1
			names.append("OvS"+str(node+1))
		else:
			names.append("s"+str(node+1))
			msg += '"s'+str(node+1)+'": { "runtime_json" : "s'+str(node+1)+'-runtime.json" }'
			num_no_sdn_topo = int(num_no_sdn_topo) + 1
		if node+1 < num_nodes: 
			msg +=',\n'
	msg +='},\n'
	msg +='"links": [\n'

	print str(names)

	#read file topology
	file_open = path+'/Topos_random/'+topology_type+'/'+str(degree)+'/'+str(num_nodes)+'/'+str(seed)+'/RyuFileEdges.txt'
	print file_open
	f = open( file_open ,'r')
	linea = f.readline()
	pon_coma = 0
	while linea != "":
		if pon_coma == 1:
			msg += ",\n"
			pon_coma = 0
		datos = linea.split(";");
		msg +='["'+str(names[int(datos[0])-1])+'","'+str(names[int(datos[1])-1])+'"]'
		linea = f.readline()
		if (linea != ""):
			pon_coma = 1;
	msg += '] \n } '
	f=open(path+'/topology.json',"w")
	f.write(msg)
	f.close()
