from waitress import serve
from api_server import app

if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=8080)
