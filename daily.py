from apscheduler.schedulers.blocking import BlockingScheduler
from app.models import User
from app import create_user_creds
import googleapiclient.discovery
from app import db
import os

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'
REQ = {
    'topicName': os.getenv('TOPIC')
}

sched = BlockingScheduler()

@sched.scheduled_job('cron', hour=0, minute=0)
def scheduled_job():
    print("Timer called")
    users = User.query.all()

    for user in users:

        # Load credentials from the session.
        credentials = create_user_creds(user)

        gmail = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)

        watch_response = str(gmail.users().watch(userId='me', body=REQ).execute())
        print("Watch renewed at: " + watch_response)

        user.token = credentials.token
        user.refresh_token = credentials.refresh_token
        db.session.commit()


sched.start()