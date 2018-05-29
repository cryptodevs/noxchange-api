```text
 /$$   /$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$$
| $$$ | $$ /$$__  $$| $$  / $$ /$$__  $$| $$  | $$ /$$__  $$| $$$ | $$ /$$__  $$| $$_____/
| $$$$| $$| $$  \ $$|  $$/ $$/| $$  \__/| $$  | $$| $$  \ $$| $$$$| $$| $$  \__/| $$
| $$ $$ $$| $$  | $$ \  $$$$/ | $$      | $$$$$$$$| $$$$$$$$| $$ $$ $$| $$ /$$$$| $$$$$
| $$  $$$$| $$  | $$  >$$  $$ | $$      | $$__  $$| $$__  $$| $$  $$$$| $$|_  $$| $$__/
| $$\  $$$| $$  | $$ /$$/\  $$| $$    $$| $$  | $$| $$  | $$| $$\  $$$| $$  \ $$| $$
| $$ \  $$|  $$$$$$/| $$  \ $$|  $$$$$$/| $$  | $$| $$  | $$| $$ \  $$|  $$$$$$/| $$$$$$$$
|__/  \__/ \______/ |__/  |__/ \______/ |__/  |__/|__/  |__/|__/  \__/ \______/ |________/
```

# NOXCHANGE API

This is a Flask application using PostgreSQL database

# API Methods

## User 

POST /api/:version/user/register fields [username, password, email]
GET  /api/:version/user/:id
POST /api/:version/user/:token fields [username, password]
POST /api/:version/user/forgot fields [email]
PUT  /api/:version/user [username, password]

## Market
POST /api/:version/market/khipu

## Operations 
POST /api/:version/sale/request
Posible states:
    * SALE_MIN_REQUESTED

POST /api/:version/sale/request/[khipu]   // In this case Khipu
    * SALE_MIN_REQUEST_ABORTED
    * SALE_MIN_REQUEST_PAYED
    * SALE_NOTIFY_REQUEST

POST /api/:version/sale/escrow
    * SALE_TX_IN_PROGRESS
    * SALE_TX_REJECTED
    * SALE_TX_COMPLETED

POST /api/:version/sale/completepayment/[khipu]
    * SALE_PAY_REJECTED
    * SALE_PAY_OK

POST /api/:version/sale/escrow/transfer
    * SALE_TRANSFER_ESCROW_OK
    * SALE_TRANSFER_ESCROW_REJECTED
    * SALE_COMPLETED

## Payments
POST /api/:version/khipu

## Important 

Use: pip install pip==9.0.3 
pip >= 10 has some problems like:
    AttributeError: 'module' object has no attribute 'get_installed_distributions'

