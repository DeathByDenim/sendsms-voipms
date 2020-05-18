#!/usr/bin/env python3

import sys
import socket
import random
import string
import datetime
import hashlib

# Insert account info from VoIP.ms here
SERVER = ""
USER_NAME = ""
PASSWORD = ""

SERVER_IP = socket.gethostbyname(SERVER)
PORT = 5060
VERBOSE = False

def random_branch():
    allowed = string.ascii_letters + string.digits
    # Branches are required to start with this magic code
    branch = "z9hG4bK."
    branch += "".join(random.choices(allowed, k=9))
    return branch

def random_call_id():
    allowed = string.ascii_letters + string.digits
    call_id = "".join(random.choices(allowed, k=12))
    return call_id

def get_ip():
    # From https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def send_message(target_phone, text_message):
    # We need both a unique brancn and Call-ID for communiticating with a SIP server
    branch = random_branch()
    call_id = random_call_id()
    local_ip_address = get_ip()
    from_tag = random_call_id()

    # SIP communications are numbered. Things can arrive out of order with UDP
    # That's not really a concern here, but still part of the SIP protocol.
    cseq=1

    # First message does not have authentication
    message=(
        "MESSAGE sip:" + target_phone + "@" + SERVER + " SIP/2.0\r\n" +
        "Via: SIP/2.0/UDP " + local_ip_address + ":" + str(PORT) + ";branch=" + branch + ";rport\r\n" +
        "From: <sip:" + USER_NAME + "@" + SERVER + ">;tag=" + from_tag + "\r\n" +
        "To: sip:" + target_phone + "@" + SERVER + "\r\n" +
        "CSeq: " + str(cseq) + " MESSAGE\r\n" +
        "Call-ID: " + call_id + "\r\n" +
        "Max-Forwards: 70\r\n" +
        "Content-Type: text/plain\r\n" +
        "Content-Length: " + str(len(text_message)) + "\r\n" +
        "Date: " + datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\n" +
        "User-Agent: sendsms-voipms 0.1\r\n" +
        "\r\n" +
        text_message + "\r\n" +
        "\r\n")

    if VERBOSE:
        print("===SENDING===")
        print(message)
        print()

    # Using UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(message.encode('utf-8'), (SERVER_IP, PORT))

    d = s.recvfrom(2048)

    if VERBOSE:
        print("===RECEIVED===")
        print(d[0].decode('utf-8'))
        print()

    if d[1][0] != SERVER_IP or d[1][1] != PORT:
        print("ERROR: Message received from different server than contacted")
        sys.exit(1)

    answer = d[0].decode('utf-8').split("\r\n")
    nonce = None
    realm = None
    uri = None

    response_code = None
    if answer[0].startswith("SIP/2.0"):
        response_code = answer[0].split(' ')[1]

    if response_code == None:
        print("ERROR: No response code in response from SIP server for first attempt")
        sys.exit(1)
    elif response_code == "202":
        # 202 means accepted
        print("Message sent")
        sys.exit(0)
    elif response_code != "401":
        # 401 means unauthorized so we need to authenticate now. Fail on any other code
        print("ERROR: Received response_code \"" + answer[0][8:] + "\" for first attempt")
        sys.exit(1)

    # Decode the answer from the SIP server to get the info needed for authentication
    for line in answer:
        if line.startswith("WWW-Authenticate:"):
            for field in line[17:].split(','):
                keyvalue = field.strip().split('=')
                if keyvalue[0].strip() == "nonce":
                    # Nonce is used to encode password
                    nonce = keyvalue[1].strip()
                    if nonce[0] == '"' and nonce[-1] == '"':
                        nonce = nonce[1:-1]
                elif keyvalue[0].strip() == "realm":
                    # Realm is name of the server and used for encoding password
                    realm = keyvalue[1].strip()
                    if realm[0] == '"' and realm[-1] == '"':
                        realm = realm[1:-1]
                elif keyvalue[0].strip() == "uri":
                    # URI is the receiver and also use for encoding password
                    uri = keyvalue[1].strip()
                    if uri[0] == '"' and uri[-1] == '"':
                        uri = uri[1:-1]
                elif keyvalue[0].strip() == "Digest algorithm":
                    # This is the encoding mechanism. Only MD5 is supported here
                    digest = keyvalue[1].strip()
                    if digest[0] == '"' and digest[-1] == '"':
                        digest = digest[1:-1]
                    if digest != "MD5":
                        print("Unsupported authentication algorithm")
                        sys.exit(1)
            break

    if uri == None:
        uri = "sip:" + target_phone + "@" + SERVER

    # Encode the password according to https://en.wikipedia.org/wiki/Digest_access_authentication
    HA1 = hashlib.md5()
    HA1.update(":".join([USER_NAME, realm, PASSWORD]).encode('utf-8'))
    HA2 = hashlib.md5()
    HA2.update(":".join(["MESSAGE", uri]).encode('utf-8'))
    response = hashlib.md5()
    response.update(":".join([HA1.hexdigest(), nonce, HA2.hexdigest()]).encode('utf-8'))

    cseq += 1

    # Second message is almost the same as the first, but now with authentication
    message=(
      "MESSAGE sip:" + target_phone + "@" + SERVER + " SIP/2.0\r\n" +
      "Via: SIP/2.0/UDP " + local_ip_address + ":" + str(PORT) + ";branch=" + branch + ";rport\r\n" +
      "From: <sip:" + USER_NAME + "@" + SERVER + ">;tag=" + from_tag + "\r\n" +
      "To: sip:" + target_phone + "@" + SERVER + "\r\n" +
      "CSeq: " + str(cseq) + " MESSAGE\r\n" +
      "Call-ID: " + call_id + "\r\n" +
      "Max-Forwards: 70\r\n" +
      "Content-Type: text/plain\r\n" +
      "Content-Length: " + str(len(text_message)) + "\r\n" +
      "Date: " + datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %Z") + "\r\n" +
      "User-Agent: sendsms-voipms 0.1\r\n" +
      "Authorization:  Digest realm=\"" + SERVER + "\", nonce=\"" + nonce + "\", algorithm=MD5, username=\"" + USER_NAME + "\",  uri=\"sip:" + target_phone + "@" + SERVER + "\", response=\"" + response.hexdigest() + "\"\r\n" +
      "\r\n" +
      text_message + "\r\n" +
      "\r\n")

    if VERBOSE:
        print("===SENDING===")
        print(message)
        print()

    s.sendto(message.encode('utf-8'), (SERVER_IP, PORT))
    d = s.recvfrom(2048)

    if VERBOSE:
        print("===RECEIVED===")
        print(d[0].decode('utf-8'))
        print()

    if d[1][0] != SERVER_IP or d[1][1] != PORT:
        print("ERROR: Message received from different server than contacted")
        sys.exit(1)

    answer = d[0].decode('utf-8').split("\r\n")
    response_code = None
    if answer[0].startswith("SIP/2.0"):
        response_code = answer[0].split(' ')[1]

    if response_code == None:
        print("ERROR: No response code in response from SIP server for second attempt")
        sys.exit(1)
    elif response_code == "202":
        # 202 means accepted
        print("Message sent")
        sys.exit(0)
    else:
        print("ERROR: Received response_code \"" + answer[0][8:] + "\" for second attempt")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0].split('/')[-1]} [phone number] [message]")
        sys.exit(1)

    phone_number = ''.join(c for c in sys.argv[1] if c.isdigit())
    if len(phone_number) > 1 and phone_number[0] == '1':
        phone_number = phone_number[1:]
    if len(phone_number) != 10:
        print("ERROR: phone number needs to be 10 digits")
        sys.exit(1)

    message = sys.argv[2]
    if len(message) == 0:
        print("ERROR: message is empty")
        sys.exit(1)

    send_message(phone_number, sys.argv[2])
