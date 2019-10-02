import flask, os, random, string
from flask import Flask, Response, request, render_template
from flask import session, redirect, url_for, escape

from http.cookies import SimpleCookie
from datetime import datetime, timedelta

## Is it necessary to set app.secret_key to some byte value?
app = Flask(__name__)

## Flip this flag for prod builds.
debug = True

# This code does not seem necessary
# import flask_login
# login_manager = flask_login.LoginManager()
# login_manager.init_app(app)

user_sessions = {}
next_sid = 0

SESSION_LIFESPAN = 30 # seconds

def generate_auth_token():
    return ''.join(random.SystemRandom().choice(
        string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32))

def dict_to_string(d):
    return '; '.join(['%s=%s' % (str(x), str(y)) for x,y in d.items()])

def cookie_to_dict(c):
    if c is None:
        return c

    cookie = SimpleCookie()
    cookie.load(c)
    return {k:v.value for (k, v) in cookie.items()}

## Verify user login cookie
## Returns 1 if cookie information is valid,
## 0 if the session is expired, and
## -1 if the session does not exist or is cookie token is invalid
## 
## If returning 0, expire the user session
## TODO(P3): determine if this can just return True / False.
def validate_login_cookie():
    global user_sessions
    cookie = cookie_to_dict(request.cookies.get('site-test-cookie'))
    if cookie is None:
        return -1
    cookie['sid'] = int(cookie['sid'])
    if cookie['sid'] not in user_sessions:
        return -1
    session = user_sessions[cookie['sid']]
    if session['expiration'] < datetime.now():
        ## Remove expired session
        user_sessions.pop(cookie['sid'])
        return 0
    if session['token'] != cookie['token']:
        return -1
    return 1

## Returns the provided session.
## Assumes the session exists: should only be run following a call
## to validate_login_cookie()
def get_session():
    cookie = cookie_to_dict(request.cookies.get('site-test-cookie'))
    return user_sessions[int(cookie['sid'])]
    
@app.route('/')
def index():
    if validate_login_cookie() == 1:
        return '<p>Logged in as %s<p><a href="/logout">Logout</a>' % (
            escape(get_session()['user']))
    return '<p>You are not logged in<p><a href="/login">Login</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    global next_sid, user_sessions
    if validate_login_cookie() == 1:
        return '''<p>You are already logged in.</p><p><a href="/">Go back</a></p>'''
    
    if request.method == 'POST':
        login_result = redirect(url_for('index'))
        token = generate_auth_token()
        login_result.set_cookie('site-test-cookie',
            dict_to_string({'sid': next_sid, 'token': token}),
            max_age=SESSION_LIFESPAN)
        user_sessions[next_sid] = {'user': request.form['username'],
            'token': token,
            'expiration': datetime.now() + timedelta(seconds=SESSION_LIFESPAN)
        }
        next_sid += 1
        return login_result
    return '''<form method="post">
            <p><input type=text name=username>
            <p><input type=submit value=Login>
        </form>'''

@app.route('/logout')
def logout():
    global user_sessions
    # Remove session if it exists
    cookie = request.cookies.get('site-test-cookie')
    if cookie is not None:
        user_sessions.pop(int(cookie_to_dict(cookie)['sid']))
    return redirect(url_for('index'))

if __name__ == '__main_':
    port = int(os.environ.get('PORT', Server.PORT))
    app.run(host=Server.HOST, port=port, debug=debug)