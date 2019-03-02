from apscheduler.schedulers.blocking import BlockingScheduler
from app.models import User

sched = BlockingScheduler()

@sched.scheduled_job('cron', hour=13, minute=6)
def scheduled_job():
    users = User.query.all

    for user in users:
        print(user.email)

sched.start()