from flask import Flask, render_template, request, redirect, url_for, session
from models import db_session, User
from authlib.integrations.flask_client import OAuth
import os
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


app = Flask(__name__)

app.secret_key = os.getenv('SECRETE_KEY')

# Configure OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email profile'},
    # access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    # authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v1/userinfo', 
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

@app.route('/service')
def service():
    return render_template('service.html')

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        loginEmail = request.form['email']
        loginPassword = request.form['password']

        
        user = db_session.query(User).filter_by(email=loginEmail).first()
        
        if user and user.verify_password(loginPassword):
            session['loggedin'] = True
            session['id'] = user.userID
            session['firstname'] = user.firstName
            msg = 'Logged in successfully!'
            return render_template('index.html', messages={"msg": msg, "email": user.email})
        else:
            msg = 'Incorrect username / password!'
    
    return render_template('login.html', msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        email = request.form['email']
        password = request.form['password']
        
        user = db_session.query(User).filter_by(email=email).first()
        if user:
            msg = 'Email already registered!'
        elif not firstName or not lastName or not email or not password:
            msg = 'Please fill out the form completely!'
        else:
            hashed_password = User.hash_password(password)
            
            new_user = User(firstName=firstName, lastName=lastName, email=email, password=hashed_password)
            
            db_session.add(new_user)
            db_session.commit()
            
            msg = 'You have successfully registered!'
            return redirect(url_for('login'))
    
    return render_template('register.html', msg=msg)


@app.route('/login/google')
def google_login():
    try:
        # state = secrets.token_urlsafe(32)  # Generate a secure random state
        # session['state'] = state
        return google.authorize_redirect(redirect_uri=url_for('auth_callback', _external=True))
        # return google.authorize_redirect(redirect_uri=url_for('auth_callback', _external=True), state=state)
    except Exception as e:
        app.logger.error("Error loggin in with google ", e)
        return redirect(url_for('auth_callback'))


@app.route('/auth/callback')
def auth_callback():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    email = user_info['email']
    firstname = user_info['given_name']
    lasttname = user_info['family_name']

    if 'email' in session:
        return render_template('login.html', email=email)

    user = db_session.query(User).filter_by(email=email).first()
    if  not user:
        user1 = User(firstName=firstname, lastName=lasttname, email=email, password=os.getenv('SECRETE_PASSWORD'))
        db_session.add(user1)
        db_session.commit()

    session['email'] = email
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/')

if __name__ == '__main__':
    app.run()