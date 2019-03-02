from apscheduler.schedulers.blocking import BlockingScheduler
from app.models import User

sched = BlockingScheduler()

@sched.scheduled_job('cron', hour=12, minuite=59)
def scheduled_job():
    print('This job is run every day at midnight')

sched.start()