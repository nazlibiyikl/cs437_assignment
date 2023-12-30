"""from flask import Flask, render_template, url_for, request, session, redirect

from flask_pymongo import PyMongo 
import bcrypt

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, validators"""

from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from wtforms import StringField, PasswordField, validators
from flask_wtf.csrf import CSRFProtect  # Note: You only need one of these
from flask_wtf import FlaskForm, RecaptchaField
import bcrypt
from google_recaptcha import ReCaptcha



from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, validators


#from google.cloud import recaptchaenterprise_v1
#from google.cloud.recaptchaenterprise_v1 import Assessment



app = Flask(__name__)

app. config['MONGO_DBNAME']= 'cs437'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/cs437'

app.config['RECAPTCHA_PUBLIC_KEY'] = '6Ld4hz8pAAAAAAdb1JvLP0H0aSizWYkKn3hdA2Dl'

app.config['WTF_CSRF_SECRET_KEY'] = 'a_random_string'
recaptcha = ReCaptcha(app=app)

mongo = PyMongo(app)
#csrf = CSRFProtect(app)
limiter = Limiter(app)

class RecoveryForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    recaptcha = RecaptchaField()

def verify_recaptcha(token):
    return recaptcha.verify(token)

def generate_code(self, data: str) -> str:
    if self.site_key is not None and '__SITE_KEY' in data:
        return data.replace('__SITE_KEY', self.site_key)
    else:
        # Handle the case where __SITE_KEY is not in data or self.site_key is None
        return data



@app.route('/')
def index():
    if 'username' in session:
        site_key = app.config['RECAPTCHA_PUBLIC_KEY']
        recaptcha_code = recaptcha.generate_code('<div class="g-recaptcha" data-sitekey="__SITE_KEY"></div>', site_key)
        return render_template('main.html', username=session['username'], recaptcha_code=recaptcha_code)
    return render_template('index.html')

"""
@app.route('/login', methods=["POST"])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name': request.form['username']})
    if login_user:
        if bcrypt.checkpw(request.form['pass'].encode('utf-8'), login_user['password'].encode('utf-8')) == login_user['password'].encode('utf-8'):
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password' """


@app.route('/login', methods=["POST"])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name': request.form['username']})
    if login_user:
        if bcrypt.checkpw(request.form['pass'].encode('utf-8'), login_user['password']):
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'
    return 'Invalid username or password'  # Add a return statement here for the case where login_user is None
        

@app.route('/login', methods=["GET"])
def show_login():
    return render_template('index.html')

"""
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method== 'POST':
        users=mongo.db.users
        existing_user = users.find_one({'name': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            users.insert ({'name' :request.form[ 'username'], 'password' :hashpass })
            session['username'] = request.form['username']
            return redirect (url_for ('index'))
        return 'Username already in database'
    return render_template('register.html') """

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users_collection = mongo.db.users
        existing_user = users_collection.find_one({'name': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            users_collection.insert_one({'name': request.form['username'], 'password': hashpass})
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        return 'Username already in database'
    return render_template('register.html')

"""@app.route('/recover_password', methods=['GET', 'POST'])
@limiter.limit("2 per day")  # Example: Allow 2 recovery attempts per day
def recover_password():
    form = RecoveryForm()

    if form.validate_on_submit():
        # Process the form data here, including CAPTCHA validation
        username = form.username.data
        # Perform password recovery logic here
        # Send recovery email, reset token, etc.
        return f'Recovery email sent for {username}. Check your inbox.'

    return render_template('recover_password.html', form=form)"""

"""@app.route('/recover_password', methods=['GET', 'POST'])
@limiter.limit("2 per day")
def recover_password():
    form = RecoveryForm()

    if form.validate_on_submit():
        # Verify reCAPTCHA token
        recaptcha_token = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_token):
            return 'Invalid reCAPTCHA. Please try again.'

        # Perform password recovery logic here
        # Send recovery email, reset token, etc.
        return 'Recovery email sent. Check your inbox.'

    return render_template('recover_password.html', form=form)"""

@app.route('/recover_password', methods=['GET', 'POST'])
@limiter.limit("2 per day")
def recover_password():
    form = RecoveryForm()

    if form.validate_on_submit():
        # Validate reCAPTCHA here
        if form.recaptcha.data:
            # Perform password recovery logic here
            # Send recovery email, reset token, etc.
            return 'Recovery email sent. Check your inbox.'

    return render_template('recover_password.html', form=form)




"""def create_assessment(
    project_id: str, recaptcha_key: str, token: str, recaptcha_action: str
) -> Assessment:
    """"""Create an assessment to analyze the risk of a UI action.
    Args:
        project_id: Your Google Cloud Project ID.
        recaptcha_key: The reCAPTCHA key associated with the site/app
        token: The generated token obtained from the client.
        recaptcha_action: Action name corresponding to the token.
  

    client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()

    # Set the properties of the event to be tracked.
    event = recaptchaenterprise_v1.Event()
    event.site_key = recaptcha_key
    event.token = token

    assessment = recaptchaenterprise_v1.Assessment()
    assessment.event = event

    project_name = f"projects/{project_id}"

    # Build the assessment request.
    request = recaptchaenterprise_v1.CreateAssessmentRequest()
    request.assessment = assessment
    request.parent = project_name

    response = client.create_assessment(request)

    # Check if the token is valid.
    if not response.token_properties.valid:
        print(
            "The CreateAssessment call failed because the token was "
            + "invalid for the following reasons: "
            + str(response.token_properties.invalid_reason)
        )
        return

    # Check if the expected action was executed.
    if response.token_properties.action != recaptcha_action:
        print(
            "The action attribute in your reCAPTCHA tag does"
            + "not match the action you are expecting to score"
        )
        return
    else:
        # Get the risk score and the reason(s).
        # For more information on interpreting the assessment, see:
        # https://cloud.google.com/recaptcha-enterprise/docs/interpret-assessment
        for reason in response.risk_analysis.reasons:
            print(reason)
        print(
            "The reCAPTCHA score for this token is: "
            + str(response.risk_analysis.score)
        )
        # Get the assessment name (id). Use this to annotate the assessment.
        assessment_name = client.parse_assessment_path(response.name).get("assessment")
        print(f"Assessment name: {assessment_name}")
    return response"""


if __name__ == '__main__':
    app.secret_key='secretivekeyagain'
    app.run(debug=True)