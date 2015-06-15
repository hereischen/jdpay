# JDPAY
------
##Overview
This is an unofficial python JingDong pay API, it contains 4 main classes:
> * PayAccount
> * PayRequest 
> * RefundRequest
> * QueryRequest
> * Notification

------

Installation
------------

Install using pip:

```bash
pip install jdpay
```
or you can refer to https://github.com/hereischen/JDPAY/dist
download the tar file.

API
---
**PayAccount**
It allows switching between differnt payment account methods such as debit card only (DO) or debit and credit card (DC).
``` python
from jdpay import PayAccount

pay_account = PayAccount(DC)

```
pay acoount will be initialised to a serious settings that support both debit card and credit card.


**PayRequest**
Post payment data
``` python
from jdpay import PayRequest

jd_pay = PayRequest(pay_account)
form_data = jd_pay.post(pay_params)

```

**QueryRequest**
This class handles paymment queries.
``` python
from jdpay import QueryRequest

query_request = QueryRequest(pay_account)

```
**RefundRequest**
This class handles refund requests.
``` python
from jdpay import RefundRequest

refund_request = RefundRequest(pay_account)

```

**Notification**
This class handls notifications send from JingDong. 
``` python
return_dict, trade_dict = Notification(notification_account).get_notification(resp)

```

------
