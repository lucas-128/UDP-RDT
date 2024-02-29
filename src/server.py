import os
import socket
import sys
import sigint_handler
import logging
import concurrent.futures
import logger

HELP_MSG = """usage: start-server [-h] [-v | -q] [-H ADDR] [-p PORT] [-s DIRPATH]

<command description>

optional arguments:
  -h, --help      show this help message and exit
  -v, --verbose   increase output verbosity
  -q, --quiet     decrease output verbosity
  -H, --host      server IP address
  -p, --port      server port
  -s, --storage   storage dir path
"""

UPLOAD = "upload"
DOWNLOAD = "download"
STOPWAIT = "2"
SELECTIVEREPEAT = "1"
SYN_REQUEST = "SYN"

class Server:
    _MAX_FILESIZE = 10000000 #10 Megabytes
    _BUFSIZE = 10000
    _DATA_SIZE = 1000
    _SYNC_SIGNAL = "sync".encode("utf8")
    _ACK_SIGNAL = "ack".encode("utf8")
    _FILENAME = "recv_file"

    def __init__(self, address: str, port: str, logger):
        self._skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._address = (address, port)
        self._skt.bind(self._address)
        self.dir_path = ""
        self.active_clients = []
        self._logger = logger

    def run(self):
        print("Server listening in "+self._address[0]+":"+str(self._address[1]))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            while True:
                # Receive incoming messages and submit them to the thread pool
                data, addr = self._skt.recvfrom(self._BUFSIZE)
                header, payload = data.decode('utf-8').split(';')
                future = executor.submit(self.handle_request,header,payload,addr)
                future.add_done_callback(lambda f: f.result())
            
    def handle_request(self, header, payload, client_addr):

        # Ignore a repeated request message from the same client.
        if client_addr in self.active_clients:
            return
        
        self.active_clients.append(client_addr)
        self._logger.info(client_addr[0],"Listen client.")

        header = header.split(',')
        payload = payload.encode('utf-8')

        request_type = header[0]
        action = header[1]
        action_mode = header[2]
        filename = header[3]
        file_size = 0
        if len(header) > 4:
            file_size = header[4]   

        if request_type != SYN_REQUEST:
            return -1
        
        if action == UPLOAD:
            if action_mode == STOPWAIT:
                # Client requests upload s&w
                self._logger.debug(client_addr[0],"Client upload file with STOP AND WAIT protocol")
                self.handle_sw_upload(client_addr,filename, file_size)
                self.active_clients.remove(client_addr)
                #print("Stop & Wait upload from client_addr finished") # Log
                return 0
            elif action_mode == SELECTIVEREPEAT:
                # Client requests upload sr
                self._logger.debug(client_addr[0],"Client upload file with SELECTIVE REPEAT protocol")
                self.handle_sr_upload(client_addr,filename, file_size)
                self.active_clients.remove(client_addr)
                #print("Selective repeat upload from client_addr finished") # Log
                return 0
            else:
                # Err action mode
                return -1
        elif action == DOWNLOAD:
            if action_mode == STOPWAIT:
                # Client requests upload s&w
                self._logger.debug(client_addr[0],"Client download file with STOP AND WAIT protocol")
                self.handle_sw_download(filename,client_addr)
                self.active_clients.remove(client_addr)
                #print("Stop & Wait download to client_addr finished") # Log
                return 0
            elif action_mode == SELECTIVEREPEAT:
                # Client requests download sr
                self._logger.debug(client_addr[0],"Client download file with SELECTIVE REPEAT protocol")
                self.handle_sr_download(filename,client_addr)
                self.active_clients.remove(client_addr)
                #print("SR download to client_addr finished") # Log
                return 0
            else:
                # Err action mode
                return -1
        else:
            # Err Action
            return -1
    
    def handle_sw_upload(self, client_addr,filename,file_size):

        # Create new socket
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.bind((self._address[0],0)) # 0 to asign to random port 
        skt.settimeout(0.5)

        reply_msg = ""
        is_deny = False

        if int(file_size) >= self._MAX_FILESIZE:
            reply_msg = "deny,;[]".encode()
            is_deny = True
        else:
            reply_msg = "ack,;[]".encode()
            is_deny = False

        times_sent = 0
        maximum_retransmissions = 20    

        file_path = self.dir_path + filename
        f = open(file_path, 'wb')

        last_written_segment = 0
        bytes_received = 0 

        while True:
            try:
                # Reply
                skt.sendto(reply_msg,client_addr)
                packet, addr = skt.recvfrom(self._BUFSIZE)
                # Parse the packet
                header, payload = packet.split(b';', 1)
                header = header.decode().split(',')
                type = header[0]

                if type == "ack":
                    f.close()
                    skt.close()
                    os.remove(file_path)
                    return

                elif type == "DATA":
                    self._logger.debug(client_addr[0],"Write data")
                    f.write(payload)
                    bytes_received = bytes_received + len(payload)
                    last_written_segment = last_written_segment+1
                    ack_packet = 'ack,' + str(last_written_segment+1) + ";[]"
                    ack_packet = ack_packet.encode()
                    skt.sendto(ack_packet,client_addr)
                    break

            except socket.timeout:
                self._logger.warning(client_addr[0],"Timeout waiting for packet")
                skt.sendto(reply_msg,client_addr)
                times_sent = times_sent + 1
                if is_deny:
                    if times_sent >= maximum_retransmissions:
                        return
                

        while bytes_received < int(file_size):
                try:
                    # Receive the packet from the socket
                    packet, addr = skt.recvfrom(self._BUFSIZE)

                    # Parse the packet
                    header, payload = packet.split(b';', 1)
                    header = header.decode().split(',')

                    # Check if its a Data packet
                    if header[0] == 'DATA':
                        # Write the payload bytes to a file
                        if int(header[1]) == last_written_segment+1:
                            self._logger.debug(client_addr[0],"Write data")
                            f.write(payload)
                            bytes_received = bytes_received + len(payload)
                            last_written_segment = last_written_segment+1
                            ack_packet = 'ack,' + str(last_written_segment+1) + ";[]"
                            ack_packet = ack_packet.encode()
                            skt.sendto(ack_packet,client_addr)
                        else:
                            ack_packet = 'ack,' + str(last_written_segment+1) + ";[]"
                            ack_packet = ack_packet.encode()
                            skt.sendto(ack_packet,client_addr)
                    
                except socket.timeout:
                    self._logger.warning(client_addr[0],"Timeout waiting for packet" )


        f.close()
        skt.close()
        self._logger.debug(client_addr[0],"File and socket closed.")
        print("File: ",filename, " downloaded into: ", self.dir_path, "using STOP & WAIT")
    
    def handle_sw_download(self,filename,client_addr):

        filepath = self.dir_path + filename

        #open file
        f = open(filepath, "rb") 
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0, os.SEEK_SET)

        # Create new socket
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.bind((self._address[0],0)) # 0 to asign to random port 
        skt.settimeout(0.5)

        maximum_retransmissions = 25
        packets_to_send = (file_size // 1024) + 1
        times_sent =  [0] * packets_to_send

        # Send file
        segment_index = 0
        self._logger.info(client_addr[0],"Starting to send file " + filename)
        while True:
            data = f.read(1024)
            if not data:
                self._logger.debug(client_addr[0],"Not data file "+filename)
                break
            segment_index += 1
            is_ack = False
            while not is_ack:
                # Send data message, and check expected ack.
                header = 'DATA,' + str(segment_index) + ',' + str(file_size) + ';'
                packet = header.encode() + data 
                skt.sendto(packet, client_addr)
                times_sent[segment_index-1] = times_sent[segment_index-1]+1
                is_ack = self.check_ack(skt,segment_index+1,packet,client_addr,times_sent,maximum_retransmissions)
            if f.tell() == file_size:
                self._logger.debug(client_addr[0],"File "+filename + " read")
                break

        f.close()
        self._logger.info(client_addr[0],str(segment_index) + " segments sent.")
        self._logger.info(client_addr[0],"Download finished.")
        skt.close()
        
    def handle_sr_upload(self,client_addr,filename, file_size):

        # Create new socket
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.bind((self._address[0],0)) # 0 to asign to random port 
        skt.settimeout(0.5)

        reply_msg = ""
        is_deny = False

        if int(file_size) >= self._MAX_FILESIZE:
            reply_msg = "deny,;[]".encode()
            is_deny = True
        else:
            reply_msg = "ack,;[]".encode()
            is_deny = False

        times_sent = 0
        maximum_retransmissions = 20   

        expected_seg_num = 0
        packet_buffer = {}
        bytes_received = 0 

        file_path = self.dir_path + filename
        f = open(file_path, 'wb')

        while True:
            try:
                # Reply
                skt.sendto(reply_msg,client_addr)
                packet, addr = skt.recvfrom(self._BUFSIZE)
                # Parse the packet
                header, payload = packet.split(b';', 1)
                header = header.decode().split(',')
                type = header[0]

                if type == "ack":
                    f.close()
                    skt.close()
                    os.remove(file_path)
                    return

                elif type == "DATA":
                    seg_num = int(header[1])
                    if seg_num == expected_seg_num:
                        # Write the expected segment into the file
                        self._logger.debug(client_addr[0],"Write data")
                        f.write(payload)
                        bytes_received = bytes_received + len(payload)
                        # Update the expected segment number
                        expected_seg_num = expected_seg_num+1
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        skt.sendto(ack_packet,client_addr)
                        # Check if there are any buffered packets that can now be added to the received packets list
                        while expected_seg_num in packet_buffer:
                            data_segment = packet_buffer[expected_seg_num]
                            bytes_received = bytes_received + len(data_segment)
                            f.write(data_segment)
                            del packet_buffer[expected_seg_num]
                            expected_seg_num = expected_seg_num + 1
                        break
                    # Caso 1. expected seg num es mayor al recibido
                    elif seg_num < expected_seg_num:
                        # Ignoro el paquete
                        # Mando el ack para ese paquete
                        self._logger.debug(client_addr[0],"Segment ignored.")
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        skt.sendto(ack_packet,client_addr)
                        break
                    # Caso 2. expected_seg_num es menor al recibido
                    elif seg_num > expected_seg_num:
                        # Agrego el packete fuera de orden al buffer
                        # Mando el ack para ese paquete
                        self._logger.debug(client_addr[0],"Segment saved out of buffer.")
                        packet_buffer[seg_num] = payload
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        skt.sendto(ack_packet,client_addr)    
                        break

            except socket.timeout:
                self._logger.warning(client_addr[0],"Timeout waiting for packet")
                skt.sendto(reply_msg,client_addr)
                times_sent = times_sent + 1
                if is_deny:
                    if times_sent >= maximum_retransmissions:
                        return
    
        while bytes_received < int(file_size):
            try:
                # Receive the packet from the socket
                packet, addr = skt.recvfrom(self._BUFSIZE)
                # Parse the packet
                header, payload = packet.split(b';', 1)
                header = header.decode().split(',')

                # Check if its a Data packet
                if header[0] == 'DATA':
                    seg_num = int(header[1])
                    if seg_num == expected_seg_num:
                        # Write the expected segment into the file
                        self._logger.debug(client_addr[0],"Write data")
                        f.write(payload)
                        bytes_received = bytes_received + len(payload)
                        # Update the expected segment number
                        expected_seg_num = expected_seg_num+1
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        skt.sendto(ack_packet,client_addr)
                        # Check if there are any buffered packets that can now be added to the received packets list
                        while expected_seg_num in packet_buffer:
                            data_segment = packet_buffer[expected_seg_num]
                            bytes_received = bytes_received + len(data_segment)
                            f.write(data_segment)
                            del packet_buffer[expected_seg_num]
                            expected_seg_num = expected_seg_num + 1
                    # Caso 1. expected seg num es mayor al recibido
                    elif seg_num < expected_seg_num:
                        # Ignoro el paquete
                        # Mando el ack para ese paquete
                        self._logger.debug(client_addr[0],"Segment ignored.")
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        skt.sendto(ack_packet,client_addr)
                    # Caso 2. expected_seg_num es menor al recibido
                    elif seg_num > expected_seg_num:
                        # Agrego el packete fuera de orden al buffer
                        # Mando el ack para ese paquete
                        self._logger.debug(client_addr[0],"Segment saved out of buffer.")
                        packet_buffer[seg_num] = payload
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        skt.sendto(ack_packet,client_addr)    
            except socket.timeout:
                self._logger.warning(client_addr[0],"Timeout waiting for packet.")

        print("File: ",filename, " downloaded into: ", self.dir_path, "using SELECTIVE REPEAT")
       
    def handle_sr_download(self,filename,client_addr):

        filepath = self.dir_path + filename
   
        #open file
        f = open(filepath, "rb") 
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0, os.SEEK_SET)

        # Create new socket
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.bind((self._address[0],0)) # 0 to asign to random port 
        skt.settimeout(0.5)

        data = f.read()
        
        packet_size = 1024 
        packets = [data[i:i+packet_size] for i in range(0, len(data), packet_size)]
        times_sent =  [0] * len(packets)
        maximum_retransmissions = 20
        acks = [0] * len(packets)
        window_size = 5
        window_start = 0

        while not all(acks):

            # Send unacknowledged packets in the window
            for i in range(window_start, window_start+window_size):
                idx = i % len(packets)
                if not acks[idx]:
                    header = 'DATA,' + str(idx) + ',' + str(file_size) + ';'
                    packet = header.encode()+ packets[idx] 
                    skt.sendto(packet, client_addr)
                    if times_sent[idx] >= maximum_retransmissions:
                        acks[idx] = 1 
                    else:
                        times_sent[idx] = times_sent[idx] + 1
                    
            # Wait for acks
            try:
                while True:
                    data, addr = skt.recvfrom(self._DATA_SIZE)
                    header, payload = data.decode('utf-8').split(';')
                    header = header.split(',')
                    if len(header) > 1 and header[1].isnumeric():
                        acks[int(header[1])] = 1
                        break
            except socket.timeout:
                pass
            
            # Advance the window 
            while window_start < len(packets) and acks[window_start]:
                window_start = window_start +  1
    
    # Create the storage directory if it does not exist. 
    def init_storage_path(self, dir_path):
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        self.dir_path = dir_path + '/'

    def check_ack(self,skt,expected_ack_num,packet,client_addr,times_sent,maximum_retransmissions):
        try:
            data, addr = skt.recvfrom(self._DATA_SIZE)
            header, payload = data.decode('utf-8').split(';')
            header = header.split(',')

            if len(header) > 1 and header[1].isnumeric() and int(header[1]) == expected_ack_num:
                return True

        except socket.timeout:
            skt.sendto(packet, client_addr)
            # Check if packet surpassed maximum retransmissions limit
            if times_sent[expected_ack_num-2] >= maximum_retransmissions:
                return True
            times_sent[expected_ack_num-2] = times_sent[expected_ack_num-2]+1