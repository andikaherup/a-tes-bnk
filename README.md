# Django MyInfo Integration

## Overview

This Django web application demonstrates integration with the MyInfo v4 APIs provided by the Singapore Government Technology Agency (GovTech). The project showcases how to implement backend APIs and Django views for retrieving personal information using the MyInfo authentication flow.

## Features

- MyInfo v4 API Integration
- OAuth 2.1 Authorization Flow
- Proof Key for Code Exchange (PKCE) Support
- Secure Token and Person Data Retrieval

## Prerequisites

- Python 3.8+
- pip
- virtualenv (recommended)

## Installation

1. Clone the repository:

```bash
git clone <your-repository-url>
cd myinfo-django-project
```

2. Create and activate a virtual environment:

```bash
python3 -m venv env
source env/bin/activate  # On Windows, use `env\Scripts\activate`
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

1. Set up environment variables:

   - `MYINFO_CLIENT_ID`: Your MyInfo Client ID
   - `MYINFO_PRIVATE_KEY_SIG`: Private signing key for client assertion
   - `MYINFO_PRIVATE_KEY_ENC`: Private encryption key

2. Update `myinfo/settings.py` with your specific configurations:
   - Adjust `MYINFO_SCOPE` as needed
   - Modify API endpoint URLs if required

## Running the Application

```bash
python -m pytest  # Run tests
python manage.py runserver localhost:3001  # Start development server on port 3001 since myinfo only recognize port 3001 for localhost
```

## MyInfo API Usage Example

```python
from myinfo.client import MyInfoPersonalClientV4
from django.utils.crypto import get_random_string

# Generate OAuth state and callback URL
oauth_state = get_random_string(length=16)
callback_url = "http://localhost:3001/callback"

# Create MyInfo client
client = MyInfoPersonalClientV4()

# Get authorization URL
authorize_url = client.get_authorise_url(oauth_state, callback_url)

# After user authentication, retrieve person data
auth_code = "your-auth-code-from-callback"
person_data = client.retrieve_resource(auth_code, oauth_state, callback_url)
```

## Evaluation Criteria

The project will be assessed on:

1. Extensibility and separation of concerns
2. Simplicity and readability
3. Test coverage
4. Error handling and robustness

## Security Considerations

- Implements OAuth 2.1 with PKCE
- Uses client assertions for authentication
- Supports encryption and signing of payloads

## Reference

- [MyInfo v4 API Documentation](https://api.singpass.gov.sg/library/myinfo/developers/overview)
- [MyInfo Demo App](https://github.com/singpass/myinfo-demo-app-v4)

## Troubleshooting

- Ensure all environment variables are correctly set
- Verify client credentials and keys
- Check network connectivity to MyInfo APIs

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the ISC License.

## Contact

Project Maintainer - [andika / andikaherup@gmail.com]
