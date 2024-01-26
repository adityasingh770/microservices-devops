import jwt, datetime, os
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
    curser = mysql.connection.curser()
    result = curser.execute(
        f'SELECT email, password FROM user WHERE email={auth.username}'
    )

    if result > 0:
        user_row = curser.fetchone()
        # email = user_row[0]
        password = user_row[1]

        # check the validity of provided password
        if auth.password != password:
            return 'Invalid credentials', 401
        else:
            return createJWT(auth.username, os.environ.get('JWT_SECRET'), True)
    else:
        return 'Invalid credentials! No user found with the provided username', 401


def createJWT(username, secret, admin):
    return jwt.encode(
        {
            'username': username,
            'expiration': datetime.datetime.now(tz=datetime.datetime.utc)
            + datetime.timedelta(days=1),
            'issued_at': datetime.datetime.utcnow(),
            'admin': admin
        },
        secret,
        algorithm='HS256'
    )
