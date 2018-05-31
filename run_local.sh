#!/bin/bash
export db=localhost
export MAIL_ADDRESS=noxchange.test@gmail.com
export MAIL_PWD=zuperSecur3!
export SECRET=acbd18db4cc2f85cedef654fccc4a4d8
export DB_URI=postgresql://postgres@$db:5432/postgres
export PORT=5000
export LOCAL=True
python noxchange_api.py