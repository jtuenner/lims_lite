# scheduler.py (Root Directory)
import time
import logging
from app.utils.logging import setup_logging
from app.utils.tasks import run_scheduler

if __name__ == "__main__":
    # Initialize logging so output goes to your logs/lims.log file
    logger = setup_logging()
    logger.info("Starting Dedicated Scheduler Process...")
    
    try:
        # This function (from app/utils/tasks.py) contains the "while True" loop
        run_scheduler()
    except KeyboardInterrupt:
        logger.info("Scheduler stopped by user.")
    except Exception as e:
        logger.exception(f"Scheduler crashed: {e}")