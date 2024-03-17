import jwt
from datetime import datetime, timedelta
import pytz
import os
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

# config
server.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
server.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
server.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
server.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')
server.config['MYSQL_PORT'] = os.environ.get('MYSQL_PORT')


@server.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth:
        return 'Missing credential', 401

    # check DB for username and password
    cursor = mysql.connection.cursor()
    result = cursor.execute(
        f'SELECT email, password FROM user WHERE email={auth.username}'
    )

    if result > 0:
        user_row = cursor.fetchone()
        # email = user_row[0]
        password = user_row[1]

        # check the validity of provided password
        if auth.password != password:
            return 'Invalid credentials', 401
        else:
            return createJWT(auth.username, os.environ.get('JWT_SECRET'), True)
    else:
        return 'Invalid credentials! No user found with the provided username', 401


@server.route('/validate', methods=['POST'])
def validate():
    encoded_jwt = request.headers['Authorization']
    if not encoded_jwt:
        return 'Missing JWT token', 401

    encoded_jwt = encoded_jwt.split(' ')[1]
    try:
        decoded = jwt.decode(
            encoded_jwt,
            os.environ.get('JWT_SECRET'),
            algorithm='HS256'
        )
    except Exception as e:
        print(e)
        return 'Failed to authorize using Token', 403
    return decoded, 200


def createJWT(username, secret, admin):
    utc_now = datetime.now(pytz.utc)
    expiration = utc_now + timedelta(days=1)
    issued_at = utc_now
    return jwt.encode(
        {
            'username': username,
            'expiration': expiration.isoformat(),
            'issued_at': issued_at.isoformat(),
            'admin': admin
        },
        secret,
        algorithm='HS256'
    )


if __name__ == '__main__':
    server.run(host='0.0.0.0', port=5000)
