from apscheduler.schedulers.blocking import BlockingScheduler
from app.models import User

sched = BlockingScheduler()

@sched.scheduled_job('cron', hour=13, minute=3)
def scheduled_job():
    print('This job is run every day at midnight')

sched.start()