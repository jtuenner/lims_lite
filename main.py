# main.py
import uvicorn
from app.config import APP_ENV

# Note: The 'app' object is imported from the app package, 
# which is initialized in app/__init__.py
from app import app

if __name__ == "__main__":
    # In development mode, enable auto-reload for a better coding experience
    is_dev = APP_ENV == "development"
    
    print(f"--- Starting LIMS Lite in {APP_ENV} mode ---")
    
    uvicorn.run(
        "app:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=is_dev,
        log_level="info",
        proxy_headers=True, # Important for Linux hosting behind Nginx
        forwarded_allow_ips="*"
    )