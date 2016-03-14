# -*- coding: utf-8 -*-
import json
import base64
import urllib
from llt.utils import smart_str

from Crypto.Hash import SHA256
from OpenSSL.crypto import load_pkcs12, FILETYPE_PEM, dump_privatekey, dump_certificate
from M2Crypto import BIO, X509, SMIME


seller_info = {
    'customer_code': "360080002191800017", 'customer_type': "CUSTOMER_NO"}
payee_info = {
    "payee_bank_code": "ABC",
    "customer_no": "360080002191800017",
    "extend_params": "{\"ssss\":\"ssss\"}",
    "payee_account_type": "P",
    "return_params": "1234ssddffgghhj",
    "trade_currency": "CNY",
    "pay_tool": "TRAN",
    "category_code": "20jd222",
    "payee_account_no": "6222600210011817312",
    "payee_account_name": "张米克",
    "trade_source": "testetst",
    "notify_url": "http://test/",  # 商户处理数据的异步通知地址
    "biz_trade_no": "2015003456",
    "out_trade_no": "23456587692",  # 外部交易号
    "seller_info": json.dumps(seller_info),
    "out_trade_date": "20150519T103700",
    "trade_amount": "1",

    "payee_bank_fullname": "农业银行",
    "request_datetime": "20150519T103700",
    "trade_subject": "test代付",
    "payee_card_type": "DE",
    "payee_mobile": "1333333333",
}


class JdDefray(object):

    def __init__(self, payee):
        self.payee_info = payee_info
        self.url = 'https://mapi.jdpay.com/npp10/defray_pay'
        self.seller_info = {'customer_code': "360080002729510013",
                            'customer_type': "CUSTOMER_NO"}
        self.param = {'customer_no': '360080002729510013',
                      'sign_type': 'SHA-256',
                      'encrypt_type': 'RSA'
                      }

    def param_sorter(self, param_dict):
        keys = param_dict.keys()
        keys.sort()
        sorted_str = ''
        for key in keys:
            value = param_dict[key]
            sorted_str += '%s=%s&' % (key, value)
        sorted_str = smart_str(sorted_str[:-1])
        return sorted_str

    def sha256(self, string, sha256_key):
        sha_hash = SHA256.new(string + sha256_key)
        hex_hash = sha_hash.hexdigest()
        return hex_hash

    def openssl_load_pkcs12_certs(self, cert_path, passphrase):
        with open(cert_path, 'rb') as f:
            c = f.read()
        pkcs7 = load_pkcs12(c, passphrase)
        # type_ 是 FILETYPE_PEM 或者 FILETYPE_ASN1 (for DER)
        type_ = FILETYPE_PEM
        p7_certificate = dump_certificate(type_, pkcs7.get_certificate())
        p7_private_key = dump_privatekey(type_, pkcs7.get_privatekey())
        # get CSR fields
        # csr_fields = pkcs7.get_certificate().get_subject().get_components()

        return p7_certificate, p7_private_key

    def pkcs7_sign(self, data, pri_key, signer_cert):
        data_bio = BIO.MemoryBuffer(data)
        key_bio = BIO.MemoryBuffer(pri_key)
        cert_bio = BIO.MemoryBuffer(signer_cert)
        signer = SMIME.SMIME()
        signer.load_key_bio(key_bio, cert_bio)
        p7 = signer.sign(data_bio, flags=SMIME.PKCS7_NOATTR)
        out = BIO.MemoryBuffer()
        p7.write_der(out)
        pkcs7_sign = out.getvalue()

        return base64.b64encode(pkcs7_sign)

    def pkcs7_encrypt(self, data, pub_key):
        data_bio = BIO.MemoryBuffer(data)
        s = SMIME.SMIME()
        x509 = X509.load_cert(pub_key, X509.FORMAT_DER)
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)
        s.set_cipher(SMIME.Cipher('des_ede3_cbc'))
        p7 = s.encrypt(data_bio, flags=SMIME.PKCS7_BINARY)
        out = BIO.MemoryBuffer()
        p7.write_der(out)
        encrypt_data = out.getvalue()

        # print base64.b64encode(encrypt_data)
        return base64.b64encode(encrypt_data)

    def post(self):
        self.param['submit'] = 'SUBMIT'
        param_str = self.param_sorter(self.payee_info)
        signature = self.sha256(param_str, sha256_key)
        pkcs7_cert, pkcs7_pri_key = self.openssl_load_pkcs12_certs(you1ke_pfx, you1ke_psw)
        signed_data = self.pkcs7_sign(param_str, pkcs7_pri_key, pkcs7_cert)
        # may need to be decode
        #signed_data = base64.decodestring(signed_data)
        encrypt_data = self.pkcs7_encrypt(signed_data, pub_key_cer)
        self.param['sign_data'] = signature
        self.param['encrypt_data'] = encrypt_data
        print self.param

        result = urllib.urlopen(self.url, urllib.urlencode(self.param)).read()
        print result


JdDefray(payee_info).post()
