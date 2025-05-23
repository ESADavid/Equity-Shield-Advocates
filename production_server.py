import os
from waitress import serve
from src.api_server import app
from werkzeug.middleware.proxy_fix import ProxyFix
import logging.config
from logging.handlers import RotatingFileHandler
from flask_cors import CORS

# Configure logging
log_file_path = os.getenv('LOG_FILE', '/var/log/equity-shield/api.log')
log_dir = os.path.dirname(log_file_path)

if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'format': '{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}',
            'datefmt': '%Y-%m-%dT%H:%M:%S%z'
        }
    },
    'handlers': {
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': log_file_path,
            'maxBytes': int(os.getenv('LOG_MAX_SIZE', 104857600)),  # 100MB
            'backupCount': int(os.getenv('LOG_BACKUP_COUNT', 10)),
            'formatter': 'json'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json'
        }
    },
    'root': {
        'handlers': ['file', 'console'],
        'level': os.getenv('LOG_LEVEL', 'INFO')
    }
})

logger = logging.getLogger(__name__)

# Configure CORS
cors_origins = os.getenv('CORS_ORIGINS', '*').split(',')
CORS(app, resources={
    r"/*": {
        "origins": cors_origins,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-KEY"]
    }
})

# Trust proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

if __name__ == '__main__':
    try:
        # Get configuration from environment
        host = os.getenv('HOST', '0.0.0.0')
        port = int(os.getenv('PORT', '5001'))
        threads = int(os.getenv('WAITRESS_THREADS', '4'))
        
        logger.info(f"Starting production server on {host}:{port} with {threads} threads")
        
        # Start Waitress server
        serve(
            app,
            host=host,
            port=port,
            threads=threads,
            url_scheme='https',
            channel_timeout=30,
            cleanup_interval=30,
            connection_limit=1000,
            max_request_header_size=262144,  # 256KB
            url_prefix=''
        )
    except Exception as e:
        logger.error(f"Server failed to start: {str(e)}", exc_info=True)
        raise
