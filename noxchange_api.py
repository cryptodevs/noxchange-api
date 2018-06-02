import boto3, os, time, datetime, random, hashlib, logging, json
import simple_khipu
from flask import Flask,abort, request, jsonify, g, url_for
from flask_httpauth import HTTPTokenAuth
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy.sql import func
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
LOCAL = os.getenv('LOCAL')

version = "0.1"

auth = HTTPTokenAuth(scheme='Token')
db = SQLAlchemy(app)

# 1 hour
jwt = Serializer(app.config['SECRET_KEY'], expires_in=3600)


@app.route('/')
def hello():
    s = """<pre>
 /$$   /$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$$
| $$$ | $$ /$$__  $$| $$  / $$ /$$__  $$| $$  | $$ /$$__  $$| $$$ | $$ /$$__  $$| $$_____/
| $$$$| $$| $$  \ $$|  $$/ $$/| $$  \__/| $$  | $$| $$  \ $$| $$$$| $$| $$  \__/| $$      
| $$ $$ $$| $$  | $$ \  $$$$/ | $$      | $$$$$$$$| $$$$$$$$| $$ $$ $$| $$ /$$$$| $$$$$   
| $$  $$$$| $$  | $$  >$$  $$ | $$      | $$__  $$| $$__  $$| $$  $$$$| $$|_  $$| $$__/   
| $$\  $$$| $$  | $$ /$$/\  $$| $$    $$| $$  | $$| $$  | $$| $$\  $$$| $$  \ $$| $$      
| $$ \  $$|  $$$$$$/| $$  \ $$|  $$$$$$/| $$  | $$| $$  | $$| $$ \  $$|  $$$$$$/| $$$$$$$$
|__/  \__/ \______/ |__/  |__/ \______/ |__/  |__/|__/  |__/|__/  \__/ \______/ |________/
    </pre>
    <h2>Welcome to NOXCHANGE API ;) <h2>
    """
    return s

""" USER API """

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    password_hash = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(32), index=True, unique=True)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


    def generate_auth_token(self, expiration=3600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'username': self.username})

    @staticmethod
    def send_email(user, pwd, recipient, subject, body):
        import smtplib

        FROM = user
        TO = recipient if type(recipient) is list else [recipient]
        SUBJECT = subject
        TEXT = body

        # Prepare actual message
        message = """From: %s\nTo: %s\nSubject: %s\n\n%s
        """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.ehlo()
            server.starttls()
            server.login(user, pwd)
            server.sendmail(FROM, TO, message)
            server.close()
            print('successfully sent the mail')
        except:
            print("failed to send mail")


@auth.verify_token
def verify_token(token):
    g.user = None
    try:
        data = jwt.loads(token)
    except:
        return False
    if 'username' in data:
        if User.query.filter_by(username=data['username']).first() is not None:
            return True
    return False


@app.route('/api/{0}/user/register'.format(version), methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    if User.query.filter_by(email=email).first() is not None:
        abort(400)    # existing email
    user = User(username=username)
    user.email = email
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/api/{0}/user/<int:id>'.format(version))
@auth.login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'id':user.id, 'username': user.username, 'email': user.email})

@app.route('/api/{0}/user/token'.format(version), methods=['POST'])
def get_auth_token():    
    email = request.json.get('email')
    password = request.json.get('password')

    
    if email is None or password is None:
        abort(400)    # missing arguments
    if not User.query.filter_by(email=email).first() is not None:
        abort(400) # It doesn't exists

    user = User.query.filter_by(email=email).first()
    if not user.verify_password(password):
        abort(400) # Password doesn't match

    token = user.generate_auth_token()
    return jsonify({'token': token.decode('ascii'), 'duration': 3600})


@app.route('/api/{0}/user/forgot'.format(version), methods=['POST'])
def forgot_password():
    """Send email with new password"""
    email = request.json.get('email')
    if email is None:
        abort(400)
    
    user = User.query.filter_by(email=email).first()    
    if user is None:
        abort(400)

    new_pwd = "%016x" % random.getrandbits(64)
    user.password_hash =  pwd_context.encrypt(new_pwd)
    db.session.commit()

    admin_user = os.getenv("MAIL_ADDRESS","noxchange.test@gmail.com")
    admin_pwd = os.getenv("MAIL_PWD","zuperSecur3!")
    subject = 'Your new password'
    body = "Your new password is:{0}".format(new_pwd)
    User.send_email(admin_user, admin_pwd, email, subject, body)
    return(jsonify({'OK': '200'}), 200)


@app.route('/api/{0}/user'.format(version), methods=['PUT'])
@auth.login_required
def edit_user():
    username = request.json.get('username')
    email = request.json.get('email')
    if email is None:
        abort(400)
    
    user = User.query.filter_by(username=username).first()  
    if user is None:
        abort(400)
    # Only can change email field.
    user.email = email
    db.session.commit()
    return(jsonify({'OK': '200'}), 200)

# Payments
@app.route('/api/{0}/khipu'.format(version), methods=['POST'])
def get_khipu_url():
    """
    https://khipu.com/page/api-referencia#paymentsPost
    """
    # Fields for authentication with service
    user_id = request.json.get('user_id')
    secret = request.json.get('secret')
    
    if user_id is None or secret is None:
        abort(500)

    data = {}
    # Required fields    
    if request.json.get('subject') is None or request.json.get('currency') is None \
        or request.json.get('amount') is None:
        abort(500)

    data['subject'] = request.json.get('subject')
    data['currency'] = request.json.get('currency') # CLP
    data['amount'] = request.json.get('amount')

    # Optional fields
    if request.json.get('transaction_id') is not None:
        data['transaction_id'] = request.json.get('transaction_id')
    if request.json.get('custom') is not None:
        data['custom'] = request.json.get('custom')
    if request.json.get('body') is not None:
        data['body'] = request.json.get('body')
    if request.json.get('bank_id') is not None:
        data['bank_id'] = request.json.get('bank_id')
    if request.json.get('return_url') is not None:
        data['return_url'] = request.json.get('return_url')
    if request.json.get('cancel_url') is not None:
        data['cancel_url'] = request.json.get('cancel_url')
    if request.json.get('picture_url') is not None:
        data['picture_url'] = request.json.get('picture_url')
    #!important, callback
    if request.json.get('notify_url') is not None:
        data['notify_url'] = request.json.get('notify_url')
    else:
        data['notify_url'] = '{0}api/{1}/khipu/callback'.format(request.url_root, version)
    if request.json.get('contract_url') is not None:
        data['contract_url'] = request.json.get('contract_url') 
    if request.json.get('notify_api_version') is not None:
        data['notify_api_version'] = request.json.get('notify_api_version')
    #ISO-8601 format
    if request.json.get('expires_date') is not None:
        data['expires_date'] = request.json.get('expires_date')
    if request.json.get('send_email') is not None:
        data['send_email'] = request.json.get('send_email')
    if request.json.get('payer_name') is not None:
        data['payer_name'] = request.json.get('payer_name')
    if request.json.get('payer_email') is not None:
        data['payer_email'] = request.json.get('payer_email')
    if request.json.get('send_reminders') is not None:
        data['send_reminders'] = request.json.get('send_reminders')
    if request.json.get('responsible_user_email') is not None:
        data['responsible_user_email'] = request.json.get('responsible_user_email')
    if request.json.get('fixed_payer_personal_identifier') is not None:
        data['fixed_payer_personal_identifier'] = request.json.get('fixed_payer_personal_identifier')
    if request.json.get('integrator_fee') is not None:
        data['integrator_fee'] = request.json.get('integrator_fee')
    if request.json.get('collect_account_uuid') is not None:
        data['collect_account_uuid'] = request.json.get('collect_account_uuid')
    try:
        print (json.dumps(data))
        return simple_khipu.create_payment(user_id, secret, json.dumps(data))
    
    except:
        abort(500)
    
    

@app.route('/api/{0}/khipu/check'.format(version),methods=['POST'])
def check_khipu_payment():
    # Fields for authentication with service
    user_id = request.json.get('user_id')
    secret = request.json.get('secret')
    notification_token = request.json.get('notification_token')
    if user_id is None or secret is None or notification_token is None:
        abort(500)    

    data = {
        'notification_token': notification_token
    }

    return simple_khipu.check_payment(user_id, secret, json.dumps(data))


@app.route('/api/{0}/khipu/callback', methods=['POST'])
def testreturn():
    form = request.form.to_dict()
    data = json.dumps(form)
    client = boto3.client('s3')
    key = str(int(time.time()))
    bucket = 'noxchange-khipu-dev'
    client.put_object(Body=data, Bucket=bucket, Key='khipu/{0}.txt'.format(key))
    return jsonify(test_dict)

if __name__ == '__main__':
    # Waiting for docker initialization
    if LOCAL:
        time.sleep(5)
        db.create_all()
        app.run(debug=True,host='0.0.0.0',port=int(os.getenv('PORT', 5000)))
    else:
        logging.info("HERE")
        logging.info(os.environ)  
        db.create_all()
        app.run()
        
