from authlib.integrations.flask_client import OAuth

oauth = OAuth()

google = oauth.register(
    name='google',
    client_id='174741511292-om81gfu82g7m60cgi0t832chega5e4ko.apps.googleusercontent.com/koushik',
    client_secret='GOCSPXkou-Xx4wOcRUNLs-HBid9g_1vq7h-MUsDjik',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'email profile'},
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    claims_options={
        'iss': {
            'values': ['https://accounts.google.com', 'accounts.google.com'], 
        }
    }
)