# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
import requests
from datetime import datetime
import json

from socket import socket
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

HOSTS = [
    ('', 443),
    ('', 443),
    ('', 443),
    ('m', 443),
    ('', 443),
    ('', 443),
    ('', 443),
    ('.com', 443),
    ('.net', 443),
    ('.cn', 443),
    ('.com', 443)
]

def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None
# class WeWork_Send_Msg():
#
#     # 文本类型消息
#     def send_txt(self):
#         headers = {"Content-Type": "text/plain"}
#         send_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=46569523-4830-43cd-bbf7-4bad4ecad26a"
#         send_data = {
#             "msgtype": "text",  # 消息类型
#             "text": {
#                 "content": text,  # 文本内容，最长不超过2048个字节，必须是utf8编码
# #                 "mentioned_list": ["@all"],
#                 # userid的列表，提醒群中的指定成员(@某个成员)，@all表示提醒所有人，如果开发者获取不到userid，可以使用mentioned_mobile_list
# #                 "mentioned_mobile_list": [""]  # 手机号列表，提醒手机号对应的群成员(@某个成员)，@all表示提醒所有人
#             }
#         }
#
#         res = requests.post(url=send_url, headers=headers, json=send_data)
#         print(res.text)
def send_msg(msg):
    """
    msg:要往群里发送的消息
    """
    headers = {"Content-Type": "application/json"}
    # 请求头
    url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=46569523-4830-43cd-bbf7-4bad4ecad26a"
    # Webhook地址，即机器人地址
    json = {
        "msgtype": "markdown",
        "markdown": {"content": msg}
    }
    r1 = requests.post(url=url, json=json, headers=headers)
    print(r1.text)
    json_text = {
        "msgtype": "text",
        "text": {
        "content": msg,
        #             "mentioned_list": ["",  "@all"]
        #             "mentioned_mobile_list":["199","@all"]
        }
    }
    r2 = requests.post(url=url, json=json_text, headers=headers)
    print(r2.text)

def print_basic_info(hostinfo):
    s = '''» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            hostname=hostinfo.hostname,
            peername=hostinfo.peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after
    )
    print(s)

def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


import concurrent.futures
if __name__ == '__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        for hostinfo in e.map(lambda x: get_certificate(x[0], x[1]), HOSTS):
#             print_basic_info(hostinfo)
#             print(hostinfo.cert.not_valid_after.timestamp())
            print(datetime.now().timestamp())
            print(hostinfo.cert.not_valid_after.timestamp() - datetime.now().timestamp() )
            if hostinfo.cert.not_valid_after.timestamp() - datetime.now().timestamp()  < 2592000 :
                print(' host {hostname} cant use for more than one mounth ,will vaild by  {notafter}'.format(hostname=hostinfo.hostname,notafter=hostinfo.cert.not_valid_after))
                send_msg('host： {hostname} 域名证书可用时间低于一个月 ,将于{notafter}过期'.format(hostname=hostinfo.hostname,notafter=hostinfo.cert.not_valid_after))
