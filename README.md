# Enhanced JWKS Server

A robust implementation of a JSON Web Key Set server with advanced security features.

## Key Features

- Secure user registration system
- UUID-based password generation
- Advanced encryption for sensitive data
- Request tracking and monitoring
- Frequency control system
- Comprehensive test coverage

## Setup Instructions

1. Create Python environment:
```bash
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Unix/MacOS
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Configure environment:
Create `.env` file with:
```
NOT_MY_KEY=[your-generated-key]
FLASK_APP=app.py
FLASK_ENV=development
```

4. Launch server:
```bash
python app.py
```

## API Documentation

### POST /register
Create new user account
```json
{
    "username": "string",
    "email": "string"
}
```

### POST /auth
Authenticate user
```json
{
    "username": "string",
    "password": "string"
}
```

### GET /health
System status check

## Testing

Execute tests:
```bash
coverage run -m pytest
coverage report --include="app.py"
```
## Gradebot : 90/90 Test Coverage : 90%
## Ojaswi Subedi
