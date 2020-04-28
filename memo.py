import multiprocessing
import random
import re
import string
import tqdm
import time
import fcntl
import ipaddress

from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6PacketTooBig
from scapy.sendrecv import send, sniff, sr, sr1


def random_generate_ip(ip_prefix):
    """Generate IPv6 addresses with ip prefixes given.

    Arguments:
        ip_prefix {str} -- IP prefix

    Returns:
        list -- List of IP addresses generated.
    """
    network = ipaddress.ip_network(ip_prefix)
    exploded = network.exploded
    ip = []
    array = exploded.split(':')
    n = int(array[-1].split('/')[-1])
    array[-1] = array[-1].split('/')[0]
    idx = n // 16
    left = n % 16
    for i in '02468ace':
        if array[idx] != '0000':
            s = '0' * (4 - len(array[idx])) + array[idx]
            res = ''
            for bit in s:
                tmp = str(bin(int(bit, 16)))[2:]
                tmp = '0' * (4 - len(tmp)) + tmp
                res += tmp
            res = res[:left]
            tmp = str(bin(int(i, 16))[2:])
            tmp = '0' * (4 - len(tmp)) + tmp
            res = res + tmp
            res += ''.join(random.choices('01', k=16 - len(res)))
            array[idx] = str(hex(int(res, 2)))[2:]
        else:
            array[idx] = i + ''.join(random.choices('0123456789abcdef', k=3))
        for j in range(idx + 1, 8):
            array[j] = ''.join(random.choices('0123456789abcdef', k=4))
        ip.append(ipaddress.IPv6Address(':'.join(array)).compressed)
    return ip


def send_echo_multiprocess(addr, data, index, str_f, seq=0):
    """Send echo request and sniff the reply.

    Arguments:
        addr {str} -- target address
        data {str} -- payload
        index {int} -- number of currently handling IP prefix
        str_f {list(str)} -- a list to store log strings

    Keyword Arguments:
        seq {int} -- sequence number in the ping request (default: {0})

    Returns:
        list -- list of packets received
    """
    str_f.append('--> Sending Echo Request to IP #%d, Seq = %d' % (index, seq))
    base = IPv6(dst=addr, plen=len(data) + 8)
    extension = ICMPv6EchoRequest(data=data, seq=seq)
    packet = base / extension

    send(packet, verbose=False)
    rcv = sniff(timeout=0.5, filter='src %s' % addr)
    res = []
    for i in rcv:
        res.append(i.show(dump=True))
    return res


def send_too_big_multiprocess(addr, data, index, str_f, mtu=1280):
    """Send too big packet ICMPv6 packet.

    Arguments:
        addr {str} -- target address
        data {str} -- payload
        index {int} -- number of current handling IP prefix
        str_f {list(str)} -- a list of strings that store the log

    Keyword Arguments:
        mtu {int} -- mtu value in the packet too big ICMPv6 Packet (default: {1280})
    """
    str_f.append('==> Sending TBT to IP #%d, MTU = %d' % (index, mtu))
    src = IPv6(dst=addr).src
    base = IPv6(src=addr, dst=src, plen=len(data) + 8)

    too_big_extension = ICMPv6PacketTooBig(mtu=mtu) / \
        (base / ICMPv6EchoRequest(data=data[:mtu - 96], seq=0))

    base = IPv6(dst=addr)

    too_big_packet = base / too_big_extension

    send(too_big_packet, verbose=False)


def get_fragmented_mtu(packets):
    """Infer the path mtu by the packets received from the target IP

    Arguments:
        packets {list(packets)} -- list of packets

    Returns:
        int -- value of mtu, return None if not fragmented.
    """
    if not packets:
        return None

    flag = (len(packets) > 1) and ('Fragment' in packets[1])
    if 'Fragment' not in packets[0]:
        if flag:
            return int(re.search(r'plen(.*?)\n', packets[1]).group().strip().split()[-1]) + 40
        else:
            return None

    if flag:
        return max(int(re.search(r'plen(.*?)\n', packets[0]).group().strip().split()[-1]) + 40,
                   int(re.search(r'plen(.*?)\n', packets[1]).group().strip().split()[-1]) + 40)
    else:
        return int(re.search(r'plen(.*?)\n', packets[0]).group().strip().split()[-1]) + 40


def get_fragmented_id(packets):
    """Get fragementation ID of the packets given.

    Arguments:
        packets {list(packet)} -- list of packets

    Returns:
        str -- fragmentation id
    """
    for packet in packets:
        if 'Fragment' in packet:
            return int(re.search(r'id(.*?)\n', packet).group().strip().split()[-1])
    return -1


def random_generate_data(total_length):
    """Randomly generate data in length given.

    Arguments:
        total_length {int} -- length of the whole IPv6 Packet

    Returns:
        str -- data generated.
    """
    payload_length = total_length - 40
    data_length = payload_length - 8
    return ''.join(random.choices(string.ascii_letters + string.digits, k=data_length))


def is_ascending(id):
    """Judge if the id is ascending.

    Arguments:
        id {list(int)} -- list of ids

    Returns:
        bool -- if the id is ascending.
    """
    _id = []
    for i in id:
        if i != -1 and i != -2:
            _id.append(i)
    is_ascending = True
    if len(_id) > 1:
        for i in range(len(_id) - 1):
            if _id[i] > _id[i + 1]:
                is_ascending = False
                break
        if is_ascending:
            return True
    return False


def solve_multiprocess(ip_prefix, count):
    """Work on ip prefix given.

    Arguments:
        ip_prefix {str} -- ip prefix
        count {int} -- number of currently handling IP prefix

    Returns:
        (list, list, list) -- three lists of strings storing different kind of log.
    """

    str_f = ['', '#' + str(count) + ' Working on Prefix ' + ip_prefix]
    str_g = ['#' + str(count) + ' ' + ip_prefix]
    str_h = []
    '''
    str_f : Store the detailed log.
    str_g : Store the result.
    str_h : Sotre the unreachable prefixes.
    '''

    data = random_generate_data(1300)
    ip = random_generate_ip(ip_prefix)
    n = len(ip)
    init_mtu = set()
    i = 0
    former_id = []
    '''
    Step 1:
    For every IP addresses generated, send a ping request with a total length of 1300B.
    If no reply received, delete it from the list of IP addresses;
    If the reply is fragmented, store the MTU.
    '''
    while i < n:
        rcv = send_echo_multiprocess(ip[i], data, i, str_f)
        if not rcv:
            str_f.append('IP #%d: %s is not available' % (i, ip[i]))
            del (ip[i])
            n -= 1
            continue
        _mtu = get_fragmented_mtu(rcv)
        if _mtu:
            str_f.append('<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' %
                         (i, _mtu, get_fragmented_id(rcv)))
            init_mtu.add(_mtu)
            former_id.append(get_fragmented_id(rcv))
        else:
            str_f.append(
                '<-- Receive Echo Reply from IP #%d, Not Fragmented' % i)
            former_id.append(-1)
        i += 1
    str_f.append('IP: ' + str(ip))
    str_f.append('Init MTU: ' + str(init_mtu))
    '''
    Step 2:
    Find a MTU value which satifies: 
    1280 <= MTU < min(init_mtu) 
    init_mtu are the fragmentation MTUs we got in the ping requests above.
    '''
    if len(init_mtu) > 0:
        current_mtu = min(init_mtu) - 8
    else:
        current_mtu = 1296
    minimum_mtu = 1280

    # No enough available IPs found.
    if len(ip) < 2:
        str_f.append('<!!!> No Enough Available IP Found <!!!>')
        tmp = '×'
        str_h.append('#' + str(count) + ' ' + ip_prefix)
        if current_mtu < minimum_mtu:
            tmp += '? '
        str_g.append(tmp)

        return (str_f, str_g, str_h)
    # We cannot find MTU Value which satisfies the requirement mentioned above.
    if current_mtu < minimum_mtu:
        str_f.append('<!!!> MTU Exhausted <!!!>')
        tmp = ' '.join([str(i) for i in former_id]) + ' ?'
        if is_ascending(former_id):
            tmp += '$'
        str_g.append(tmp)
        return (str_f, str_g, str_h)

    str_f.append('Current MTU: ' + str(current_mtu))

    '''
    Step 3:
    Send TBT with the MTU we got to each IP.
    Meanwhile, Check if the packet from 2nd IP already fragmented after sending TBT to 1st IP.
    '''

    flag = False # True if we can infer it's an aliased prefix by comparing the first two IPs.
    flag2 = False # True if we have problem receiving the packet from the 2nd IP.
    
    for i in range(n): # Send TBT to every IP.
        if i == 1: 
            '''
            Check if the packet from 2nd IP already fragmented after sending TBT to 1st IP.
            We should also confirm that if the MTUs are equal.
            '''
            rcv = send_echo_multiprocess(ip[i], data, i, str_f, seq=0)
            max_retries = 3 # Try three times.
            while not rcv and max_retries >= 0:
                max_retries -= 1
                str_f.append('<!> IP: %s no response, retrying... <!>' % ip[i])
                rcv = send_echo_multiprocess(ip[i], data, i, str_f, seq=0)
            if not rcv:
                str_f.append(
                    'Cannot receive echo reply from IP #1, '
                    'so we cannot decide whether it is an alised prefix by comparing '
                    'MTU of IP #0 and IP #1.')
                flag2 = True
            else:
                _mtu = get_fragmented_mtu(rcv)
                if _mtu:
                    str_f.append(
                        '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, get_fragmented_id(rcv)))
                    if _mtu == current_mtu:
                        flag = True
                else:
                    str_f.append(
                        '<-- Receive Echo Reply from IP #%d, Not Fragmented' % i)

        send_too_big_multiprocess(ip[i], data, i, str_f, mtu=current_mtu)
    '''
    Step 4:
    Send a ping request (1300B) to each IP and store each fragmentation ID.
    id = -1 -> Not fragmented;
    id = -2 -> No reply received.
    '''
    id = [-1] * n # Store the fragmentation ID of each ping reply.
    for i in range(n):
        rcv = send_echo_multiprocess(ip[i], data, i, str_f, seq=0)
        max_retries = 3
        while not rcv and max_retries >= 0:
            max_retries -= 1
            str_f.append('<!> IP: %s no response, retrying... <!>' % ip[i])
            rcv = send_echo_multiprocess(ip[i], data, i, str_f, seq=0)
        if not rcv:
            str_f.append('<!> Cannot Receive Echo Reply from IP #%d' % i)
            id[i] = -2 # No reply received.
        else:
            _mtu = get_fragmented_mtu(rcv)
            if _mtu:
                tmp = get_fragmented_id(rcv)
                id[i] = tmp
                str_f.append(
                    '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, tmp))
            else:
                str_f.append(
                    '<-- Receive Echo Reply from IP #%d, Not Fragmented' % i)

    '''
    Step 5:
    Distinguish different cases based on the information we got.
    Give mark as follows:
    $ -> Increasing fragmentation ID;
    * -> Affirm it's an aliased prefix by comparing fragmentation of the first two IPs;
    ^ -> Unable to receive reply from the 2nd IP, thus we cannot affirm whether it belongs to the case above;
    The remaining two kinds of mark are already given above:
    × -> No enough reachable IPs;
    ? -> No available MTU, i.e. Path MTU = 1280
    '''
    tmp = ' '.join([str(i) for i in id]) + ' '

    if is_ascending(id):
        tmp += '$' 

    if flag:
        str_f.append(
            'Since Echo Reply from IP #1 has been fragmented after sending TBT to IP #0, We can affirm it is an '
            'aliased prefix.')
        tmp += '*'
    if flag2:
        tmp += '^'
    str_g.append(tmp)

    return (str_f, str_g, str_h)


def write_file(array):
    """Write log to the files.

    Arguments:
        array {(list, list, list)} -- three lists of strings storing different kinds of log.
    """
    global f, g, h
    str_f, str_g, str_h = array
    fcntl.flock(f, fcntl.LOCK_EX)
    for i in str_f:
        print(i, file=f)
    fcntl.flock(f, fcntl.LOCK_UN)

    fcntl.flock(g, fcntl.LOCK_EX)
    for i in str_g:
        print(i, file=g)
    fcntl.flock(g, fcntl.LOCK_UN)

    fcntl.flock(h, fcntl.LOCK_EX)
    for i in str_h:
        print(i, file=h)
    fcntl.flock(h, fcntl.LOCK_UN)


file_no = 1
f_name = './memo/log/log_%d.txt'
g_name = './memo/result/result_%d.txt'
h_name = './memo/unreachable-prefixes/unreachable-prefixes.txt'

f = open(f_name % file_no, 'a+', encoding='utf-8')
g = open(g_name % file_no, 'a+', encoding='utf-8')
h = open(h_name, 'a+', encoding='utf-8')


def run(process_number=64, batch_size=6400):
    global file_no, f, g
    total = 629864
    count = 0
    bar = tqdm.tqdm(total=total)
    sum = 0
    with open('prefixes.txt', 'r', encoding='utf-8') as input_stream:
        while True:
            if sum >= batch_size:
                sum = sum % batch_size
                file_no += 1
                f.close()
                g.close()
                f = open(f_name % file_no, 'a+', encoding='utf-8')
                g = open(g_name % file_no, 'a+', encoding='utf-8')
            p = multiprocessing.Pool(process_number)
            lines = []
            for _ in range(process_number):
                line = input_stream.readline()
                if line:
                    lines.append(line)
                else:
                    break
            if len(lines) == 0:
                break
            for line in lines:
                count += 1
                sum += 1
                ip_prefix = line.strip()
                p.apply_async(solve_multiprocess, args=(
                    ip_prefix, count,), callback=write_file)
            p.close()
            p.join()
            bar.update(len(lines))


if __name__ == '__main__':
    run(process_number=64, batch_size=10000)
    f.close()
    g.close()
    h.close()
