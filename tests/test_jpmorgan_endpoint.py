import pytest
import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from src.api_server import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()
    yield client

API_KEY = "equity-shield-2024-secure-key"
HEADERS = {"X-API-KEY": API_KEY}

def test_get_jpmorgan_account_success(client):
    response = client.get('/api/banks/jpmorgan-chase/account', headers=HEADERS)
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success'
    assert 'data' in data
    assert 'integration' in data

def test_get_jpmorgan_account_unauthorized(client):
    response = client.get('/api/banks/jpmorgan-chase/account')
    assert response.status_code == 401
    data = response.get_json()
    assert "error" in data
