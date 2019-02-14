# -*- coding: utf-8 -*-
import os, atexit
import flask
from flask import request
from config import Config
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from pytz import utc
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import json
from datetime import datetime, timedelta
from todoist.api import TodoistAPI
from apiclient import errors
from dateutil.parser import parse
import re, pytz, logging, base64

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

REQ = {
    'labelIds': [os.getenv('GETAROUND_LABEL')],
    'labelFilterAction': 'include',
    'topicName': os.getenv('TOPIC')
}

# Local testing: ssh -R webhooks-bk-tunnel:80:localhost:5000 serveo.net
# https://webhooks-bk-tunnel.serveo.net/webhook-callback


def create_json_file(raw_json, filename):
    json_secret = json.loads(raw_json)
    with open(filename, "w") as out_file: json.dump(json_secret, out_file)

create_json_file(str(os.getenv('G_CLIENT_SECRET')), CLIENT_SECRETS_FILE)

app = flask.Flask(__name__)
app.config.from_object(Config)

# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See http://flask.pocoo.org/docs/0.12/quickstart/#sessions.
app.secret_key = os.getenv("SECRET_KEY")


db = SQLAlchemy(app)
migrate = Migrate(app, db)
from app.models import User

# @app.shell_context_processor
# def make_shell_context():
#     return {'db': db, 'User': User}

@app.route('/')
def index():
    return print_index_table()


@app.route('/test')
def test_api_request():

    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    gmail = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)


    # Call the Gmail API, watch the label
    watch_response = gmail.users().watch(userId='me', body=REQ).execute()

    start_history = watch_response['historyId']

    flask.session['credentials'] = credentials_to_dict(credentials)

    return "Complete"


@app.route('/authorize')
def authorize():
    initialize_cron_job()
    print('Initialized')
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():

    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials

    gmail = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    user_profile = gmail.users().getProfile(userId='me').execute()
    user_email = user_profile['emailAddress']

    # Call the Gmail API, watch the label
    watch_response = gmail.users().watch(userId='me', body=REQ).execute()

    start_history = watch_response['historyId']

    user_exists = db.session.query(User.email).filter_by(email=user_email).scalar() is not None
    if not user_exists:
        create_user(user_email, credentials, start_history)

    else:
        update_creds(db.session.query(User.email).filter_by(email=user_email), credentials)

    flask.session['credentials'] = credentials_to_dict(credentials)
    initialize_cron_job()

    #return flask.redirect(flask.url_for('test_api_request'))
    return "Complete"


def credentials_to_dict(credentials):
    return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


def creds_to_dict(user):
    return {'token': user.token,
        'refresh_token': user.refresh_token,
        'token_uri': user.token_uri,
        'client_id': user.client_id,
        'client_secret': user.client_secret,
        'scopes': [user.scopes]}

def create_user(user_email, credentials, start_history):
    u = User(
        email=str(user_email),
        token=str(credentials.token),
        refresh_token=str(credentials.refresh_token),
        token_uri=str(credentials.token_uri),
        client_id=str(credentials.client_id),
        client_secret=str(credentials.client_secret),
        scopes=str(credentials.scopes[0]),
        history=int(start_history))
    db.session.add(u)
    db.session.commit()

def update_creds(user, credentials):
    user.token = str(credentials.token),
    user.refresh_token = str(credentials.refresh_token),
    user.token_uri = str(credentials.token_uri),
    user.client_id = str(credentials.client_id),
    user.client_secret = str(credentials.client_secret),
    user.scopes = str(credentials.scopes)
    db.session.commit()

def print_index_table():
    return ('<table>' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '</td></tr></table>')


@app.route("/google593c268ab6c32072.html")
def verify():
     return "google-site-verification: google593c268ab6c32072.html"


@app.route("/webhook-callback", methods=['POST'])
def webhook_callback():

    envelope = json.loads(request.data.decode('utf-8'))
    payload = base64.b64decode(envelope['message']['data'])

    json_payload = payload.decode('utf8')
    data = json.loads(json_payload)

    user_email = data['emailAddress']

    user_exists = db.session.query(User.email).filter_by(email=user_email).scalar() is not None
    if not user_exists:
        return flask.redirect('authorize')

    u = User.query.filter_by(email=user_email).first()

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **creds_to_dict(u))

    gmail = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    api = initialize_todoist()
    #
    # if (request.args.get('token', '') != os.getenv('PUBSUB_VERIFICATION_TOKEN')):
    #     return 'Invalid request', 400

    try:
        history = (gmail.users().history().list(userId='me',
                                                  startHistoryId=u.history,
                                                  historyTypes='messageAdded')
                   .execute())
        changes = history['history'] if 'history' in history else []
        while 'nextPageToken' in history:
            page_token = history['nextPageToken']
            history = (gmail.users().history().list(userId='me',
                                                      startHistoryId=u.history,
                                                      pageToken=page_token, historyTypes='messageAdded').execute())
            changes.extend(history['history'])
    except errors.HttpError as error:
        print
        'An error occurred: %s' % error

    predefinedLabels = [os.getenv('GETAROUND_LABEL'), 'INBOX']

    for change in changes:
        if 'messagesAdded' in change:
            print('***In messages added: ' + str(change))
            labels = change["messagesAdded"][0]["message"]["labelIds"]
            intersectionOfTwoArrays = list(set(predefinedLabels) & set(labels))
            if set(predefinedLabels) == set(intersectionOfTwoArrays):
                message = gmail.users().messages().get(userId='me', id=change["messagesAdded"][0]["message"]["id"]).execute()
                subject = (header for header in message['payload']['headers'] if header["name"] == "Subject").__next__()['value']
                #msg_str = str(base64.urlsafe_b64decode(message['payload']['parts'][0]['body']['data'].encode('utf-8')), 'utf-8')
                #md_msg_str = md(msg_str)
                msg_id = change["messagesAdded"][0]["message"]["id"]
                msg_url = "https://mail.google.com/mail/u/0/#label/getaround/" + change["messagesAdded"][0]["message"]["id"]
                msg_str = message['snippet']

                rental_date_obj = parse(subject, fuzzy=True)
                today = get_now_user_timezone(api)
                tomorrow = today + timedelta(days=1)

                labels = [os.getenv('TODOIST_T2D_L_ID'), os.getenv('TODOIST_HOME_L_ID')]
                project_id = os.getenv('TODOIST_GETAROUND_P_ID')
                date_string = today + timedelta(minutes=15)
                rental_date_str = rental_date_obj.strftime('%I:%M')

                # Rental is today
                if today.date() == rental_date_obj.date():
                    content = 'Getaround rental today at ' + rental_date_str + ' - Clean-out car'

                # Rental is tomorrow before 9am
                if tomorrow.date() == rental_date_obj.date() and rental_date_obj.hour  <= 9:
                    content = 'Getaround rental tomorrow at ' + rental_date_str + ' - Clean-out car'

                else:
                    content = 'Getaround rental at ' + rental_date_str + ' - Clean-out car'
                    date_string = str(rental_date_obj.month) + '-' + str(rental_date_obj.day)

                item = add_task(api, project_id, content, date_string, labels)
                api.notes.add(item['id'], "[Link to message](" + msg_url + ") -  " + msg_str)

                # Get text between Return and Duration then remove the PST (which is an unrecognized tz)
                return_date_obj = parse((msg_str.split("Return:")[1]).split("Duration:")[0].rsplit(' ',2)[0], fuzzy=True)
                return_date_str = return_date_obj.strftime('%I:%M')

                content = 'Getaround return at ' + return_date_str + ' - Clean-out car'
                date_string = return_date_obj + timedelta(minutes=30)
                labels = [os.getenv('TODOIST_HOME_L_ID')]
                add_task(api, project_id, content, date_string, labels)
                print('******************Task created: ', content)
                api.commit()


    #Reset start history



    u.history = data['historyId']

    # Returning any 2xx status indicates successful receipt of the message.
    return 'OK', 200

def add_task(api, project_id, content, date_str, labels):
    item = api.items.add(content,
                         project_id,
                         date_string=date_str,
                         labels=labels)
    api.commit()
    return item

def initialize_todoist():
    API_TOKEN = get_token()
    if not API_TOKEN:
        logging.warn('Please set the API token in environment variable.')
        exit()
    api = TodoistAPI(API_TOKEN)
    api.sync()
    return api


def get_token():
    token = os.getenv('TODOIST_APIKEY')
    return token


# Get current time in user's timezone
def get_now_user_timezone(api):
    user_timezone = get_user_timezone(api)
    return datetime.now(tz=user_timezone)


# Get user's timezone
def get_user_timezone(api):
    todoist_tz = api.state["user"]["tz_info"]["timezone"]
    match = re.search("GMT( ((\+|\-)(\d+)))?", todoist_tz)

    if match:
        if match.group(3) == '+': operation = '-'
        else: operation = '+'
        GMT_tz = 'Etc/GMT' + operation + match.group(4)
        return pytz.timezone(GMT_tz)

    else: return pytz.timezone(api.state["user"]["tz_info"]["timezone"])

def watch():
    # Call the Gmail API, watch the label

    users = User.query.all()

    for user in users:
        credentials = creds_to_dict(user)
        gmail = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)
        watch_response = str(gmail.users().watch(userId='me', body=REQ).execute())
        print("Watch renewed at: " + watch_response)

# Create scheduled job to run daily
def initialize_cron_job():
    scheduler = BackgroundScheduler(timezone=utc)
    scheduler.add_job(watch, 'cron', hour=14, minute=25)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run('localhost', 5000, debug=True)