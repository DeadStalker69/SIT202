import socket

ip = "127.0.0.1"
port = 53


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("starting server")

s.bind((ip, port))

def decode_domain_name(data, offset):
    domain = ""
    while True:
        length = data[offset]
        if length == 0:
            break
        elif length & 0xc0 == 0xc0:
            ptr_offset = ((length & ~0xc0) << 8) | data[offset + 1]
            domain += decode_domain_name(data, ptr_offset)[0]
            offset += 2
            break
        else:
            domain += data[offset + 1:offset + 1 + length].decode('utf-8') + "."
            offset += length + 1
    return domain, offset

def buildresponse(data, addr):
    # parse the request message
    transaction_id = data[:2]
    flags = b'\x81\x80'
    questions = data[4:6]
    answer_rrs = b'\x00\x01'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'
    ip_address = addr[0]
    
    # build the response message
    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    response += data[12:]
    
    # add the IP address to the answer section
    response += b'\xc0\x0c' + b'\x00\x01' + b'\x00\x01' + b'\x00\x00' + b'\x00\x04' + socket.inet_aton(ip_address)
    
    # set the length field in the message header
    length = len(response)
    response = response[:2] + (length).to_bytes(2, byteorder='big') + response[4:]
    
    # remove the EDNS0 record from the additional section
    response = response[:len(response)-20]

    return response

while 1:
    data, addr = s.recvfrom(512)
    dns = buildresponse(data, addr)

    s.sendto(dns, addr)
