/*P4-16*
 *Hybrid domain discovery protocol : HDDP*/


#include <core.p4>
#include <v1model.p4>



const bit<16> TYPE_REQUEST = 1;//Indicates we do have a request packet for the OpCode
const bit<16> TYPE_REPLY = 2;//Indicates we do have a reply packet for the OpCode
const bit<16> TYPE_ACK = 3;//Indicates we do have a ACK packet for the OpCode
const bit<48> TIME_BLOCK = 2000000; //Time block

const bit<8> MAX_DEVICES = 31;//Maximum number of devices to discover, max number of tuples 
const bit<32> NUM_ELEM = 12461;//Number of elements in the register

const bit<8> M = 1;//Key to always matching table

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> portId_t;
typedef bit<32> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header hddp_t {
    macAddr_t Mac_ant;
    macAddr_t Last_mac;
    macAddr_t Src_mac;
    bit<16>   Opcode;
    bit<16>   Num_hops;
    time_t    Time_block;
    bit<64>   Num_Sec;
    bit<64>   Num_Ack;
}

header type_device_t{ bit<16> Type_devices;}
header id_device_t{ bit<64> id_mac_devices;}
header inport_t { portId_t inports;}
header outport_t { portId_t outports;}
header bidirectional_t { bit<8>	bidirectional;}

//Counter to parse this types header stacks
struct parser_metadata_t {
	bit<8> type_tuple;
	bit<8> id_tuple;
	bit<8> inport_tuple;
	bit<8> outport_tuple;
	bit<8> bidirectional_tuple;
}

struct metadata {
	parser_metadata_t parser_metadata;
}

struct headers {
	ethernet_t ethernet;
    hddp_t hddp;	
    type_device_t [MAX_DEVICES]   Type_devices;
    id_device_t [MAX_DEVICES]   id_mac_devices;
    inport_t [MAX_DEVICES]   inports;
    outport_t [MAX_DEVICES]   outports;
    bidirectional_t [MAX_DEVICES]   bidirectional;
}

/*************************************************************************
*********************** R E G I S T E R S ********************************
************************************************************************/

register <bit<9>> (1) register_port; //Register containing ports
register <bit<48>> (1) register_time; //Register containing timestamp
register <bit<64>> (1) register_seq;//Regiser with the sequence number 
register <macAddr_t> (1) register_ONOS;//Register to save the ONOS controller MAC direction

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser (packet_in packet,
					out headers hdr,
	                inout metadata meta,
	                inout standard_metadata_t standard_metadata) {

	//Commence parsing.
	state start {
		transition parse_ethernet;
	}
	
	//Parse ethernet header.
	state parse_ethernet {
		packet.extract(hdr.ethernet); 
		transition parse_hddp;
	}
	
	//Parse HDDP packet. If its a request: accept. If its a reply: parse the tuples to insert one.
	state parse_hddp {
		packet.extract(hdr.hddp);
		transition parse_type_device;
	}
	
	//start parsing the tuples (MAX_DEVICES) 
	state parse_type_device {
		packet.extract(hdr.Type_devices.next);
		meta.parser_metadata.type_tuple = meta.parser_metadata.type_tuple + 1;		
		transition select (meta.parser_metadata.type_tuple) {
			MAX_DEVICES: parse_id_device;
			default: parse_type_device;			
		}
	}

	state parse_id_device {
        packet.extract(hdr.id_mac_devices.next);
        meta.parser_metadata.id_tuple = meta.parser_metadata.id_tuple + 1;
        transition select(meta.parser_metadata.id_tuple) {
            MAX_DEVICES: parse_inport;
            default: parse_id_device;
        }
    }

	state parse_inport {
        packet.extract(hdr.inports.next);
        meta.parser_metadata.inport_tuple = meta.parser_metadata.inport_tuple + 1;
        transition select(meta.parser_metadata.inport_tuple) {
            MAX_DEVICES: parse_outport;
            default: parse_inport;
        }
    }

	state parse_outport {
        packet.extract(hdr.outports.next);
        meta.parser_metadata.outport_tuple = meta.parser_metadata.outport_tuple + 1;
        transition select(meta.parser_metadata.outport_tuple) {
            MAX_DEVICES: parse_bidirectional;
            default: parse_outport;
        }
    }

	state parse_bidirectional {
        packet.extract(hdr.bidirectional.next);
        meta.parser_metadata.bidirectional_tuple = meta.parser_metadata.bidirectional_tuple + 1;
        transition select(meta.parser_metadata.bidirectional_tuple) {
            MAX_DEVICES: accept;
            default: parse_bidirectional;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   **************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
	//Tables to resolve node MAC address (two as they have to be applied two times)

	action set_mac (macAddr_t nodeAddr) {
		hdr.ethernet.srcAddr = nodeAddr;
	}

	table mac_table_1 {
		key = {	M : exact;}
		actions = {set_mac;}
	}

	table mac_table_2 {
		key = { M : exact;}
	    actions = {set_mac;}
	}

	//Packet processing 
	apply {
	 	//Auxiliary variables
		bit<9>  locked_port = 0;
		bit<48>   timestamp = 0;
		bit<48> ingress_time = 0;
		bit<64>  Num_Sec = 0;
		macAddr_t ONOS_MAC = 0;
 		//Temporal value to store the switch MAC
		macAddr_t tmp_id;
		//Hash variable
        bit<32> hash_mac_src;
        bit<32> hash_mac_dst;

		ingress_time = standard_metadata.ingress_global_timestamp;

		//PACKET REQUEST PROCESSING
		if (hdr.hddp.Opcode == TYPE_REQUEST) {
			 hash(hash_mac_src, HashAlgorithm.identity, (bit<48>) 0, { hdr.ethernet.srcAddr }, (bit<48>) 1);

			//Read registers  
	        register_seq.read(Num_Sec, hash_mac_src);
    	    register_time.read(timestamp,hash_mac_src);
        	register_port.read(locked_port, hash_mac_src);
        	register_ONOS.read(ONOS_MAC, hash_mac_src);

       	 	//Check packet sequence,only accept it if it's different same if the sequence has expired.
			//if (timestamp > standard_metadata.ingress_global_timestamp) {
            //	 mark_to_drop(standard_metadata);
        	//}
			//else {
			
				//First packet recieved, same inport as the register locked one, different input port but expired timestamp.
				if (locked_port == 0 || locked_port == standard_metadata.ingress_port || locked_port != standard_metadata.ingress_port && timestamp < standard_metadata.ingress_global_timestamp ) {
					//lock port,update timestamp,save sequence number, save controller MAC
					register_port.write(hash_mac_src, standard_metadata.ingress_port);
			        register_time.write(hash_mac_src,TIME_BLOCK + ingress_time);
					register_seq.write(hash_mac_src, hdr.hddp.Num_Sec);
					register_ONOS.write(hash_mac_src, hdr.ethernet.srcAddr);
					//update num device
					hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
					//broadcast packet, trough every port but the locked one , swtmcst group to not ingress one
					standard_metadata.mcast_grp = 1;
				} 
				//Different input port and not expired timestamp triggers reply
				else  {
					//Put as source MAC address the switch MAC	
					mac_table_1.apply();	
					//Create PACKET REPLY
					hdr.hddp.Opcode = TYPE_REPLY;
					hdr.hddp.Num_hops = 1;
					//Insert tuple in new PACKET REPLY
					hdr.Type_devices[0].Type_devices = (bit<16>) 2;
		            hdr.id_mac_devices[0].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr;  
	    		    hdr.inports[0].inports = (portId_t)standard_metadata.ingress_port;
	        		hdr.outports[0].outports = (portId_t)standard_metadata.ingress_port;
	        		hdr.bidirectional[0].bidirectional = (bit<8>) 1;
					//Put as destination MAC address the ONOS MAC
					hdr.ethernet.dstAddr = ONOS_MAC;
					//Send the PACKET REPLY trough the PACKET REQUEST incoming port
					standard_metadata.egress_spec = standard_metadata.ingress_port;
			//	}			
			}
		}
	
		//PACKET REPLY PROCESSING
		else if (hdr.hddp.Opcode == TYPE_REPLY) {
        	hash(hash_mac_dst, HashAlgorithm.identity, (bit<48>) 0, { hdr.ethernet.dstAddr }, (bit<48>) 1);

      		//Read registers  
	        register_seq.read(Num_Sec, hash_mac_dst);
    	   	register_port.read(locked_port, hash_mac_dst);
	
            //Check packet sequence, if the timestamp has not expired and is a different sequence drop it.
            if (Num_Sec != hdr.hddp.Num_Sec) {
		    	mark_to_drop(standard_metadata);
			}

			else {
			//Save source macAddr
			tmp_id = hdr.ethernet.srcAddr;
   			//Change temporarly the source Adress to the switch MAC, to send as id
			mac_table_2.apply();

			//Due to limitations of BMv2 this is needed
			if (hdr.hddp.Num_hops == 1) {
				//Insert tuple in void gaps 
				hdr.Type_devices[1].Type_devices = (bit<16>) 2;
				hdr.id_mac_devices[1].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr;
				hdr.inports[1].inports =(portId_t) standard_metadata.ingress_port;
				hdr.outports[1].outports =(portId_t) locked_port; 
				hdr.bidirectional[1].bidirectional = (bit<8>) 1;
				//Increase Numdevices    
 		    	hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
				//Set back the source macAddr to the original
				hdr.ethernet.srcAddr = tmp_id;
				//Send packet trough locked port
				standard_metadata.egress_spec = locked_port;
			}
            else if (hdr.hddp.Num_hops == 2) {
                //Insert tuple in void gaps 
                hdr.Type_devices[2].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[2].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[2].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[2].outports =(portId_t) locked_port;    
                hdr.bidirectional[2].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
			}
            else if (hdr.hddp.Num_hops == 3) {
                //Insert tuple in void gaps 
                hdr.Type_devices[3].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[3].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[3].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[3].outports =(portId_t) locked_port;    
                hdr.bidirectional[3].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
			}
            else if (hdr.hddp.Num_hops == 4) {
                //Insert tuple in void gaps 
                hdr.Type_devices[4].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[4].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[4].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[4].outports =(portId_t) locked_port;    
                hdr.bidirectional[4].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
			}
            else if (hdr.hddp.Num_hops == 5) {
                //Insert tuple in void gaps 
                hdr.Type_devices[5].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[5].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[5].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[5].outports =(portId_t) locked_port;    
                hdr.bidirectional[5].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
				}
            else if (hdr.hddp.Num_hops == 6) {
                //Insert tuple in void gaps 
                hdr.Type_devices[6].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[6].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[6].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[6].outports =(portId_t) locked_port;    
                hdr.bidirectional[6].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
			}
			else if (hdr.hddp.Num_hops == 7) {
                //Insert tuple in void gaps 
                hdr.Type_devices[7].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[7].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[7].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[7].outports =(portId_t) locked_port;
                hdr.bidirectional[7].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 8) {
                //Insert tuple in void gaps 
                hdr.Type_devices[8].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[8].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[8].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[8].outports =(portId_t) locked_port;
                hdr.bidirectional[8].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 9) {
                //Insert tuple in void gaps 
                hdr.Type_devices[9].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[9].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[9].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[9].outports =(portId_t) locked_port;
                hdr.bidirectional[9].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 10) {
                //Insert tuple in void gaps 
                hdr.Type_devices[10].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[10].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[10].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[10].outports =(portId_t) locked_port;
                hdr.bidirectional[10].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 11) {
                //Insert tuple in void gaps 
                hdr.Type_devices[11].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[11].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[11].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[11].outports =(portId_t) locked_port;
                hdr.bidirectional[11].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 12) {
                //Insert tuple in void gaps 
                hdr.Type_devices[12].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[12].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[12].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[12].outports =(portId_t) locked_port;
                hdr.bidirectional[12].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 13) {
                //Insert tuple in void gaps 
                hdr.Type_devices[13].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[13].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[13].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[13].outports =(portId_t) locked_port;
                hdr.bidirectional[13].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 14) {
                //Insert tuple in void gaps 
                hdr.Type_devices[14].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[14].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[14].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[14].outports =(portId_t) locked_port;
                hdr.bidirectional[14].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 15) {
                //Insert tuple in void gaps 
                hdr.Type_devices[15].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[15].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[15].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[15].outports =(portId_t) locked_port;
                hdr.bidirectional[15].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 16) {
                //Insert tuple in void gaps 
                hdr.Type_devices[16].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[16].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[16].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[16].outports =(portId_t) locked_port;
                hdr.bidirectional[16].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 17) {
                //Insert tuple in void gaps 
                hdr.Type_devices[17].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[17].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[17].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[17].outports =(portId_t) locked_port;
                hdr.bidirectional[17].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 18) {
                //Insert tuple in void gaps 
                hdr.Type_devices[18].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[18].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[18].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[18].outports =(portId_t) locked_port;
                hdr.bidirectional[18].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 19) {
                //Insert tuple in void gaps 
                hdr.Type_devices[19].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[19].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[19].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[19].outports =(portId_t) locked_port;
                hdr.bidirectional[19].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 20) {
                //Insert tuple in void gaps 
                hdr.Type_devices[20].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[20].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[20].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[20].outports =(portId_t) locked_port;
                hdr.bidirectional[20].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 21) {
                //Insert tuple in void gaps 
                hdr.Type_devices[21].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[21].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[21].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[21].outports =(portId_t) locked_port;
                hdr.bidirectional[21].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 22) {
                //Insert tuple in void gaps 
                hdr.Type_devices[22].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[22].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[22].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[22].outports =(portId_t) locked_port;
                hdr.bidirectional[22].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 23) {
                //Insert tuple in void gaps 
                hdr.Type_devices[23].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[23].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[23].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[23].outports =(portId_t) locked_port;
                hdr.bidirectional[23].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 24) {
                //Insert tuple in void gaps 
                hdr.Type_devices[24].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[24].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[24].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[24].outports =(portId_t) locked_port;
                hdr.bidirectional[24].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 25) {
                //Insert tuple in void gaps 
                hdr.Type_devices[25].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[25].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[25].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[25].outports =(portId_t) locked_port;
                hdr.bidirectional[25].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 26) {
                //Insert tuple in void gaps 
                hdr.Type_devices[26].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[26].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[26].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[26].outports =(portId_t) locked_port;
                hdr.bidirectional[26].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 27) {
                //Insert tuple in void gaps 
                hdr.Type_devices[27].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[27].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[27].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[27].outports =(portId_t) locked_port;
                hdr.bidirectional[27].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 28) {
                //Insert tuple in void gaps 
                hdr.Type_devices[28].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[28].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[28].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[28].outports =(portId_t) locked_port;
                hdr.bidirectional[28].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 29) {
                //Insert tuple in void gaps 
                hdr.Type_devices[29].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[29].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[29].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[29].outports =(portId_t) locked_port;
                hdr.bidirectional[29].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
            else if (hdr.hddp.Num_hops == 30) {
                //Insert tuple in void gaps 
                hdr.Type_devices[30].Type_devices = (bit<16>) 2;
                hdr.id_mac_devices[30].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
                hdr.inports[30].inports =(portId_t) standard_metadata.ingress_port;
                hdr.outports[30].outports =(portId_t) locked_port;
                hdr.bidirectional[30].bidirectional = (bit<8>) 1;
                //Increase Numdevices    
                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
                //Set back the source macAddr to the original
                hdr.ethernet.srcAddr = tmp_id;
                //Send packet trough locked port
                standard_metadata.egress_spec = locked_port;
            }
//            else if (hdr.hddp.Num_hops == 31) {
//                //Insert tuple in void gaps 
//                hdr.Type_devices[31].Type_devices = (bit<16>) 2;
//                hdr.id_mac_devices[31].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
//                hdr.inports[31].inports =(portId_t) standard_metadata.ingress_port;
//                hdr.outports[31].outports =(portId_t) locked_port;
//                hdr.bidirectional[31].bidirectional = (bit<8>) 1;
//                //Increase Numdevices    
//                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
//                //Set back the source macAddr to the original
//                hdr.ethernet.srcAddr = tmp_id;
//                //Send packet trough locked port
//                standard_metadata.egress_spec = locked_port;
//            }
//            else if (hdr.hddp.Num_hops == 32) {
//                //Insert tuple in void gaps 
//                hdr.Type_devices[32].Type_devices = (bit<16>) 2;
//                hdr.id_mac_devices[32].id_mac_devices = (bit<64>)hdr.ethernet.srcAddr ;//(REVIEW)
//                hdr.inports[32].inports =(portId_t) standard_metadata.ingress_port;
//                hdr.outports[32].outports =(portId_t) locked_port;
//                hdr.bidirectional[32].bidirectional = (bit<8>) 1;
//                //Increase Numdevices    
//                hdr.hddp.Num_hops = hdr.hddp.Num_hops + 1;
//                //Set back the source macAddr to the original
//                hdr.ethernet.srcAddr = tmp_id;
//                //Send packet trough locked port
//                standard_metadata.egress_spec = locked_port;
//			}
			else {
				mark_to_drop(standard_metadata);
	        }
		  }
		}
		//Drop packet if is not a PACKET REQUEST or PACKET REPLY
		else {
			mark_to_drop(standard_metadata);
		}
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    	if (hdr.hddp.Opcode == TYPE_REQUEST && standard_metadata.egress_port == standard_metadata.ingress_port) {
	       	mark_to_drop(standard_metadata);
  		}
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply {
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    //Emit my packets in parsed order and append the rest of the packet afterwards (actually should be nothing) 
	apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.hddp);
		packet.emit(hdr.Type_devices);
    	packet.emit(hdr.id_mac_devices);
    	packet.emit(hdr.inports);
    	packet.emit(hdr.outports);
    	packet.emit(hdr.bidirectional);
    }
} 

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

