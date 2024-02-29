import socket
import os
import sigint_handler
import logger
import sys

class Client:
    _DATA_SIZE = 10000
    _SYNC_SIGNAL = "sync".encode("utf8")
    _ACK_SIGNAL = "ack".encode("utf8")
    _TIMEOUT = 0.5  # In seconds.

    def __init__(self, address: str, port: str, logger):
        self._skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._address = (address, port)
        self._skt.bind(self._address)
        self._skt.settimeout(self._TIMEOUT)
        self.dest_path = ""
        self._logger = logger


    """Client uploads the specified filename found in the specified filepath 
    into the server found at the address and port inputted using stop & wait"""
    def stop_and_wait_upload(self,filepath,filename,address,port):

        # Check si existe el archivo. Si no Loggear y salir
        if not os.path.exists(filepath):
            self._logger.debug(address,"File not found for upload.")
            return

        f = open(filepath, "rb") #open file 
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0, os.SEEK_SET)
        syn_msg = "SYN,upload,2," + filename + "," + str(file_size) + ";[]"

        maximum_retransmissions = 20
        packets_to_send = (file_size // 1024) + 1
        times_sent =  [0] * packets_to_send

        # Sync, Ack.
        is_ack = False
        while not is_ack:
            self._skt.sendto(syn_msg.encode('utf-8'), (address,int(port)))
            self._logger.info(address,"SYNC SIGNAL sent")
            ack_check = self.check_first_ack(syn_msg,address,port)
            is_ack = ack_check[0]
            sv_address = ack_check[1]
            if is_ack == True:
                break
            else:
                self._logger.info(address,"DENY received")
                self._skt.sendto("ack,;[]".encode('utf-8'), sv_address)
                return

        self._logger.info(address,"ACK received")

        # Send file
        self._logger.info(address,"Starting to send file...")
        segment_index = 0
        while True:
            data = f.read(1024)
            if not data:
                self._logger.debug(address,"Not data")
                break
            segment_index += 1
            is_ack = False
            while not is_ack:
                header = 'DATA,' + str(segment_index) + ';'
                packet = header.encode()+ data 
                self._skt.sendto(packet, sv_address)
                times_sent[segment_index-1] = times_sent[segment_index-1]+1
                is_ack = self.check_ack_sw_upload(segment_index+1,packet,sv_address,times_sent,maximum_retransmissions)
            if f.tell() == file_size:
                self._logger.debug(address,"File read")
                break
        f.close()
        self._logger.info(address,str(segment_index) + " segments sent")
        self._logger.info(address,"Upload finished")
        
    """
    Waits and checks for the initial acknowledgement.
    Returns True if Ack is received, and False on timeout.
    """
    def check_first_ack(self,syn_msg,address,port):

        while True:
            try:
                data, addr = self._skt.recvfrom(self._DATA_SIZE)
                header, payload = data.decode('utf-8').split(';')
                header = header.split(',')
                msg = header[0]
                if msg == "ack":
                    return (True,addr)
                elif msg == "deny":
                    return (False,addr)

            except socket.timeout:
                self._skt.sendto(syn_msg.encode('utf-8'), (address,int(port)))
                          
    """
    Waits and checks for an acknowledgement.
    Returns True if Ack is received, and False on timeout.
    """
    def check_ack_sw_upload(self,expected_ack_num,packet,sv_address,times_sent,maximum_retransmissions):
        data = ""
        while data != "ack":
            try:
                data, addr = self._skt.recvfrom(self._DATA_SIZE)
                header, payload = data.decode('utf-8').split(';')
                header = header.split(',')

                if len(header) > 1 and header[1].isnumeric() and int(header[1]) == expected_ack_num:
                        return True
            except socket.timeout:
                self._skt.sendto(packet, sv_address)
                # Check if packet surpassed maximum retransmissions limit
                if times_sent[expected_ack_num-2] >= maximum_retransmissions:
                    return True
                times_sent[expected_ack_num-2] = times_sent[expected_ack_num-2]+1

        return True
    
    """Client downloads the specified filename from the server and 
    stores it in the destination path using stop & wait."""
    def stop_and_wait_download(self,dest_path,filename,server_ip_addr, server_port):

        self.init_storage_path(dest_path)

        # Request download
        syn_msg = "SYN,download,2," + filename + ";[]"
        file_size = 0

        self._skt.sendto(syn_msg.encode('utf-8'), (server_ip_addr,int(server_port)))

        # Sync, Ack.
        is_ack = False
        while not is_ack:
            try:
                self._skt.sendto(syn_msg.encode('utf-8'), (server_ip_addr,int(server_port)))
                self._logger.info(server_ip_addr,"SYNC SIGNAL sent")
                packet, addr = self._skt.recvfrom(self._DATA_SIZE)
                if(len(packet) > 0):
                    # Parse the packet
                    header, payload = packet.split(b';', 1)
                    header = header.decode().split(',')
                    file_size = header[2]
                    break
            except socket.timeout:
                self._logger.debug(server_ip_addr,"Timeout waiting for packet.")
        self._logger.info(server_ip_addr,"ACK received")

        file_path = self.dest_path + filename
        f = open(file_path, 'wb')
        last_written_segment = 0
        bytes_received = 0

        while bytes_received < int(file_size):
                try:
                    # Receive the packet from the socket
                    packet, addr = self._skt.recvfrom(self._DATA_SIZE)

                    # Parse the packet
                    header, payload = packet.split(b';', 1)
                    header = header.decode().split(',')

                    # Check if its a Data packet
                    if header[0] == 'DATA':
                        # Write the payload bytes to a file
                        if int(header[1]) == last_written_segment+1:
                            self._logger.debug(server_ip_addr,"Write data")
                            f.write(payload)
                            bytes_received = bytes_received + len(payload)
                            last_written_segment = last_written_segment+1
                            ack_packet = 'ack,' + str(last_written_segment+1) + ";[]"
                            ack_packet = ack_packet.encode()
                            self._skt.sendto(ack_packet,addr)
                        else:
                            ack_packet = 'ack,' + str(last_written_segment+1) + ";[]"
                            ack_packet = ack_packet.encode()
                            self._skt.sendto(ack_packet,addr)
                    
                except socket.timeout:
                    self._logger.debug(server_ip_addr,"Timeout waiting for packet.")

        f.close()
        self._skt.close()
        self._logger.debug(server_ip_addr,"Download "+filename+ " finished")
        return 0
    
    """Client uploads the specified filename found in the specified filepath 
    into the server found at the address and port inputted using selective repeat"""
    def selective_repeat_upload(self,filepath,filename,address,port):

        if not os.path.exists(filepath):
            self._logger.debug(address,"File not found for upload.")
            return

        f = open(filepath, "rb") #open file
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0, os.SEEK_SET)

        syn_msg = "SYN,upload,1," + filename + "," + str(file_size) + ";[]"

        maximum_retransmissions = 20

        # Sync, Ack.
        is_ack = False
        while not is_ack:
            self._skt.sendto(syn_msg.encode('utf-8'), (address,int(port)))
            self._logger.info(address,"SYNC SIGNAL sent")
            ack_check = self.check_first_ack(syn_msg,address,port)
            is_ack = ack_check[0]
            sv_address = ack_check[1]
            if is_ack == True:
                break
            else:
                self._logger.info(address,"DENY received")
                self._skt.sendto("ack,;[]".encode('utf-8'), sv_address)
                return

        data = f.read()
        
        packet_size = 1024 
        packets = [data[i:i+packet_size] for i in range(0, len(data), packet_size)]
        times_sent =  [0] * len(packets)
        acks = [0] * len(packets)
        window_size = 5
        window_start = 0

        while not all(acks):
            # Send unacknowledged packets in the window
            for i in range(window_start, window_start+window_size):
                idx = i % len(packets)
                if not acks[idx]:
                    header = 'DATA,' + str(idx) + ';'
                    #print("Seg num: ", idx, "Header: ",header)
                    packet = header.encode()+ packets[idx] 
                    self._skt.sendto(packet, sv_address)
                    if times_sent[idx] >= maximum_retransmissions:
                        #print("Paquete ",idx,"supero el max retrasnmssion. Marcando como ack")
                        acks[idx] = 1 
                    else:
                        times_sent[idx] = times_sent[idx] + 1
                    
            # Wait for acks
            try:
                while True:
                    data, addr = self._skt.recvfrom(self._DATA_SIZE)
                    header, payload = data.decode('utf-8').split(';')
                    header = header.split(',')
                    #print('recibido: ',header)
                    if len(header) > 1 and header[1].isnumeric():
                        acks[int(header[1])] = 1
                        break
                   # print("Me llego ack del paqute: ",header[1], " actualizo el array")
            except socket.timeout:
                pass
            
            # Advance the window 
            while window_start < len(packets) and acks[window_start]:
                #print("Muevo la ventana")
                window_start = window_start +  1

        self._logger.info(address,str(len(packets)) + " segments sent")
        self._logger.info(address,"Upload finished")
            
    """Client downloads the specified filename from the server and 
    stores it in the destination path using selective repeat."""        
    def selective_repeat_download(self,dest_path,filename,server_ip_addr, server_port):
        
        self.init_storage_path(dest_path)

        # Request download
        syn_msg = "SYN,download,1," + filename + ";[]"
        file_size = 0

        self._skt.sendto(syn_msg.encode('utf-8'), (server_ip_addr,int(server_port)))

        # Sync, Ack.
        is_ack = False
        while not is_ack:
            try:
                self._logger.info(server_ip_addr,"SYNC SIGNAL sent")
                self._skt.sendto(syn_msg.encode('utf-8'), (server_ip_addr,int(server_port)))
                packet, addr = self._skt.recvfrom(self._DATA_SIZE)
                sv_adr = addr
                if(len(packet) > 0):
                    # Parse the packet
                    header, payload = packet.split(b';', 1)
                    header = header.decode().split(',')
                    file_size = header[2]
                    break
            except socket.timeout:
                self._logger.debug(server_ip_addr,"Timeout waiting for packet.")
        self._logger.info(server_ip_addr,"ACK received")

        file_path = self.dest_path + filename
        f = open(file_path, 'wb')
        expected_seg_num = 0
        packet_buffer = {}
        bytes_received = 0

        while bytes_received < int(file_size):
            try:
                # Receive the packet from the socket
                packet, addr = self._skt.recvfrom(self._DATA_SIZE)
                # Parse the packet
                header, payload = packet.split(b';', 1)
                header = header.decode().split(',')

                # Check if its a Data packet
                if header[0] == 'DATA':
                    seg_num = int(header[1])
                    if seg_num == expected_seg_num:
                        # Write the expected segment into the file
                        self._logger.debug(server_ip_addr,"Write data")
                        f.write(payload)
                        bytes_received = bytes_received + len(payload)
                        # Update the expected segment number
                        expected_seg_num = expected_seg_num+1
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        self._skt.sendto(ack_packet,sv_adr)
                        # Check if there are any buffered packets that can now be added to the received packets list
                        while expected_seg_num in packet_buffer:
                            data_segment = packet_buffer[expected_seg_num]
                            bytes_received = bytes_received + len(data_segment)
                            f.write(data_segment)
                            del packet_buffer[expected_seg_num]
                            expected_seg_num = expected_seg_num + 1
                    # Caso 1. expected seg num es mayor al recibido
                    elif seg_num < expected_seg_num:
                        # ignoro el paquete
                        # mando el ack para ese paquete
                        self._logger.debug(server_ip_addr,"Segment ignored.")
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        self._skt.sendto(ack_packet,sv_adr)
                    # Caso 2. expected_seg_num es menor al recibido
                    elif seg_num > expected_seg_num:
                        # agrego el packete fuera de orden al buffer
                        # mando el ack para ese paquete
                        self._logger.debug(server_ip_addr,"Segment saved out of buffer.")
                        packet_buffer[seg_num] = payload
                        ack_packet = 'ack,' + str(seg_num) + ";[]"
                        ack_packet = ack_packet.encode()
                        self._skt.sendto(ack_packet,sv_adr)    
            except socket.timeout:
                self._logger.debug(server_ip_addr,"Timeout waiting for packet.")

        f.close()
        self._skt.close()
        self._logger.debug(server_ip_addr,"Download "+filename+ " finished")

    # Create the storage directory if it does not exist. 
    def init_storage_path(self, dest_path):
        if not os.path.exists(dest_path):
            os.makedirs(dest_path)
        self.dest_path = dest_path + '/'

