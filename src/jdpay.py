# -*- coding: utf-8 -*-
import base64
import xmltodict
import json
import urllib2
import binascii
import re
import os
import logging


from llt.utils import smart_str
from Crypto.Hash import SHA256, MD5
from Crypto.Cipher import DES, DES3
from M2Crypto import RSA
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Get an instance of a logger
logger = logging.getLogger(__name__)


def get_config(name):
    """
    Get configuration variable from environment variable
    or django setting.py
    """
    config = os.environ.get(name, getattr(settings, name, None))
    if config:
        return config
    else:
        raise ImproperlyConfigured("Can't find config for '%s' either in environment"
                                   "variable or in settings.py" % name)


# SHA-256
def sha256(string):
    sha_hash = SHA256.new(string)
    hex_hash = sha_hash.hexdigest()
    return hex_hash


# RSA
def sha256_rsa_sign(string, rsa_pri_key):
    hex_hash = sha256(string)
    key = RSA.load_key(rsa_pri_key)
    signature = key.private_encrypt(hex_hash, RSA.pkcs1_padding)
    base64_crypto_sign = base64.b64encode(signature)
    return base64_crypto_sign


# DES encryption
def des_encrypt(string, deskey, charset='utf-8'):
    key = base64.b64decode(deskey)[:8]
    cipher = DES.new(key)
    plain_text = smart_str(string)
    repeat = 8 - len(plain_text) % 8
    plain_text += chr(repeat) * repeat
    encrypt_msg = cipher.encrypt(plain_text)
    b64_msg = base64.b64encode(encrypt_msg).encode(charset)
    return b64_msg


# 3DES decryption
def decrypt_trade_data(data, deskey):
    b64d_deskey = base64.b64decode(deskey)
    actual_deskey = b64d_deskey[:24]
    cipher = DES3.new(actual_deskey)
    decrypt_msg = cipher.decrypt(data)
    return decrypt_msg


def dict_to_byte(the_dict):
    org_str = json.dumps(the_dict)
    bytestr = bytearray(org_str)

    # 补位
    x = (len(org_str) + 4) % 8
    if x == 0:
        # 数据结尾不需要补位，只需添加头部的有效数据长度。
        final_bytestr = bytestr
        final_bytestr.insert(0, len(org_str))
        number_of_heading_zero = (8 - (len(final_bytestr) % 8))
        final_bytestr = bytearray(
            chr(0) * number_of_heading_zero) + final_bytestr
        return final_bytestr
    else:
        y = 8 - x
        #  数据结尾需要补位。
        final_bytestr = bytestr + bytearray(chr(0) * y)
        final_bytestr.insert(0, len(org_str))
        number_of_heading_zero = (8 - (len(final_bytestr) % 8))
        final_bytestr = bytearray(
            chr(0) * number_of_heading_zero) + final_bytestr
        return final_bytestr


class PayAccount(object):

    """
    切换账户类型的类:
        type_category = DO 时, DO: Debit only 仅支持借记卡
        type_category = DC 时, DC: Debit and credit 支持借记卡和信用卡
    """
    # in later version,type_category will be debit or credit

    def __init__(self, type_category):
        self.merchant_num = get_config(
            'CB_MERCHANT_NUM_{type}'.format(type=type_category))
        self.merchant_deskey = get_config(
            'CB_MERCHANT_DES_KEY_{type}'.format(type=type_category))
        self.merchant_md5key = get_config(
            'CB_MERCHANT_MD5_KEY_{type}'.format(type=type_category))
        self.merchant_rsa_pri_key = get_config(
            'CB_MERCHANT_RSA_PRI_KEY_FILE_{type}'.format(type=type_category))
        self.merchant_rsa_pub_key = get_config(
            'CB_MERCHANT_RSA_PUB_KEY_FILE_{type}'.format(type=type_category))
        self.merchant_wy_rsa_pub_key = get_config(
            'CB_MERCHANT_WY_RSA_PUB_KEY_FILE_{type}'.format(type=type_category))

        self.pay_url = get_config('CB_PAY_URL')

        logger.info('Current PayAccount type is %s.' % type_category)


class JDPay(object):

    def __init__(self, pay_account):
        self.pay_account = pay_account
        self.params = {}

    def set_params(self, input_dict):
        self.params = input_dict


class PayRequest(JDPay):

    """
    交易请求的类
    """

    def params_filter(self, params):
        # 除去不需要签名的项目，并声称签名原串
        self.params['merchantNum'] = self.pay_account.merchant_num
        self.params['version'] = (
            '2.0' if settings.CB_ENCRYPTION_MODE else '1.0')
        keys = self.params.keys()
        keys.sort()
        self.filtered_params = {}
        self.prestr = ''
        for key in keys:
            value = self.params[key]
            if key not in ("merchantSign", "token", "version"):
                self.filtered_params[key] = value
                self.prestr += '%s=%s&' % (key, self.filtered_params[key])

        self.prestr = smart_str(self.prestr[:-1])

    def gen_pay_merchant_sign(self):
        # 生成签名，并将签名添加回self.params.
        base64_sign = sha256_rsa_sign(
            self.prestr, self.pay_account.merchant_rsa_pri_key)

        self.params['merchantSign'] = base64_sign

    def encrypt_info(self):
        # 从view中借鉴,将字典中的敏感信息加密
        encryption_fields = ('merchantRemark', 'tradeNum', 'tradeName', 'tradeDescription',
                             'tradeTime', 'tradeAmount', 'currency',
                             'successCallbackUrl', 'failCallbackUrl', 'notifyUrl')
        for field in encryption_fields:
            self.params[field] = des_encrypt(
                self.params[field], self.pay_account.merchant_deskey)

    def post(self, input_dict):
        params = self.set_params(input_dict)
        self.params_filter(params)

        self.gen_pay_merchant_sign()

        if settings.CB_ENCRYPTION_MODE:
            self.encrypt_info()
        return self.params


class RefundandQueryBase(JDPay):

    def __init__(self, pay_account):
        super(RefundandQueryBase, self).__init__(pay_account=pay_account)
        self.url = ''
        self.request_params = {'version': '1.0',
                               'merchantNum': self.pay_account.merchant_num}
        self.res_json = ''

    def gen_encrypt_trade_data_and_sign(self):

        # 补位运算
        res = dict_to_byte(self.params)
        plain_text = ''.join(map(chr, res))

        # 3DES 加密
        b64d_deskey = base64.b64decode(self.pay_account.merchant_deskey)
        actual_deskey = b64d_deskey[:24]
        cipher = DES3.new(actual_deskey)
        self.encrypt_msg = cipher.encrypt(plain_text).encode('hex')

        self.base64_crypto_sign = sha256_rsa_sign(
            self.encrypt_msg, self.pay_account.merchant_rsa_pri_key)

    def post_request(self):
        self.request_params['data'] = self.encrypt_msg
        self.request_params['merchantSign'] = self.base64_crypto_sign

        post_json = json.dumps(
            self.request_params, ensure_ascii=True, encoding='utf-8', separators=(',', ':'))

        req = urllib2.Request(
            url=self.url, data=post_json, headers={'Content-Type': 'application/json'})
        f = urllib2.urlopen(req)
        response = f.read()
        f.close()
        self.response_dict = json.loads(response)

    def verify_merchant_sign_parse_response(self):

        if self.response_dict['resultCode'] == 0:
            res_dict = self.response_dict['resultData']
            # 1.解密签名内容
            # 此处签名为网银＋返回的签名
            b64d_sign = base64.b64decode(res_dict['sign'])
            # 对返回的签名用公钥解密得到decrypt_sign_string
            pub_key = RSA.load_pub_key(
                self.pay_account.merchant_wy_rsa_pub_key)
            decrypt_sign_string = pub_key.public_decrypt(
                b64d_sign, RSA.pkcs1_padding)

            # 2.对data进行sha256摘要加密，从而得到一个string来验证签名。
            # data 为网银＋返回的data域（尚未解密）
            data = res_dict['data']
            # print data
            sha256_source_sign_string = sha256(data)
            # 3.对比1和2的结果
            if (decrypt_sign_string == sha256_source_sign_string):
                # 验证签名通过
                hex_to_byte = binascii.unhexlify(data)

                # 3DES解密
                plain_trade_data = decrypt_trade_data(
                    hex_to_byte, self.pay_account.merchant_deskey)

                pattern = re.compile(r'{"(.+)"}')
                match = pattern.search(plain_trade_data)
                if match:
                    self.res_json = match.group()

                    self.res_json = '{"code":"0","content":' + \
                        self.res_json + '}'

                else:
                    self.res_json = '{"code":"1","content":{}}'
            else:
                # 验签失败  不受信任的响应数据
                self.res_json = '{"code":"1","content":{}}'

        else:
            self.res_json = '{"code":"1","content":{}}'

    def post(self, input_dict):
        self.set_params(input_dict)
        self.gen_encrypt_trade_data_and_sign()
        self.post_request()
        self.verify_merchant_sign_parse_response()
        return self.res_json


class RefundRequest(RefundandQueryBase):

    """
    处理退款请求

    """

    def __init__(self, pay_account):
        super(RefundRequest, self).__init__(pay_account=pay_account)
        self.url = get_config('CB_REFUND_URL')


class QueryRequest(RefundandQueryBase):

    """
    处理查询请求的类 

    """

    def __init__(self, pay_account):
        super(QueryRequest, self).__init__(pay_account=pay_account)
        self.url = get_config('CB_QUERY_URL')


class Notification(JDPay):

    """
    处理网银在线异步通知的类

    """

    def __init__(self, pay_account):
        super(Notification, self).__init__(pay_account=pay_account)

    def parse_response(self, response):
        xml = base64.b64decode(response)
        self.response_dict = xmltodict.parse(xml)["CHINABANK"]

    def gen_md5_sign(self):
        h = MD5.new()
        original_string = self.response_dict['VERSION'] + self.response_dict['MERCHANT'] + self.response_dict[
            'TERMINAL'] + self.response_dict['DATA'] + self.pay_account.merchant_md5key
        h.update(original_string)
        self.md5_signture = h.hexdigest()

    def decrypt_info(self):
        encrypted_data = base64.b64decode(self.response_dict["DATA"])
        key = base64.b64decode(self.pay_account.merchant_deskey)[:8]
        des = DES.new(key)
        res = des.decrypt(encrypted_data)
        # 去除结束标签后的字符，保证输出是一个严格意义的xml字符串
        end_index = res.find('</DATA>')
        self.decrypted_res_dict = xmltodict.parse(res[:end_index + 7])

    def get_notification(self, response):
        self.parse_response(response)
        self.gen_md5_sign()
        if self.response_dict['SIGN'] == self.md5_signture:
            self.decrypt_info()
            return self.decrypted_res_dict['DATA']['RETURN'], self.decrypted_res_dict['DATA']['TRADE']
        else:
            return {}, {}
