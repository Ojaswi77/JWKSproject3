import pytest
import json
import uuid
from app import app, setup_database
from datetime import datetime

@pytest.fixture
def test_client():
    """Create test client fixture."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        setup_database()  # Fresh database for each test
        yield client

def test_system_health(test_client):
    """Verify system health endpoint."""
    response = test_client.get('/health')
    assert response.status_code == 200
    assert response.json["status"] == "operational"

def test_user_registration_flow(test_client):
    """Test complete user registration process."""
    # Generate unique test credentials
    test_username = f"user_{datetime.now().timestamp()}"
    
    # Test successful registration
    response = test_client.post('/register', json={
        "username": test_username,
        "email": f"{test_username}@test.com"
    })
    assert response.status_code == 201
    assert "password" in response.json
    
    # Verify duplicate prevention
    duplicate_response = test_client.post('/register', json={
        "username": test_username,
        "email": f"{test_username}@test.com"
    })
    assert duplicate_response.status_code == 409

def test_authentication_process(test_client):
    """Test the authentication system."""
    # Setup test account
    test_username = f"auth_{datetime.now().timestamp()}"
    reg_response = test_client.post('/register', json={
        "username": test_username,
        "email": f"{test_username}@test.com"
    })
    test_password = reg_response.json["password"]
    
    # Test valid credentials
    auth_response = test_client.post('/auth', json={
        "username": test_username,
        "password": test_password
    })
    assert auth_response.status_code == 200
    
    # Test invalid password
    failed_response = test_client.post('/auth', json={
        "username": test_username,
        "password": "wrong_password"
    })
    assert failed_response.status_code == 401

def test_request_limiting(test_client):
    """Test request rate limiting functionality."""
    test_username = f"limit_{datetime.now().timestamp()}"
    
    # Create test account
    reg_response = test_client.post('/register', json={
        "username": test_username,
        "email": f"{test_username}@test.com"
    })
    test_password = reg_response.json["password"]
    
    # Send multiple requests
    auth_data = {
        "username": test_username,
        "password": test_password
    }
    
    responses = []
    for _ in range(12):  # Exceed limit
        response = test_client.post('/auth', json=auth_data)
        responses.append(response.status_code)
    
    # Verify rate limiting
    assert 429 in responses

def test_input_validation(test_client):
    """Test input validation and error handling."""
    # Test registration with missing data
    empty_reg = test_client.post('/register', json={})
    assert empty_reg.status_code == 400
    
    partial_reg = test_client.post('/register', json={"username": "test"})
    assert partial_reg.status_code == 400
    
    # Test authentication with missing data
    empty_auth = test_client.post('/auth', json={})
    assert empty_auth.status_code == 400
    
    partial_auth = test_client.post('/auth', json={"username": "test"})
    assert partial_auth.status_code == 400