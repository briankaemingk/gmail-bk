from app import db

class User(db.Model):

    email = db.Column(db.String, primary_key=True)
    token = db.Column(db.String)
    refresh_token = db.Column(db.String)
    token_uri = db.Column(db.String)
    client_id = db.Column(db.String)
    client_secret = db.Column(db.String)
    scopes = db.Column(db.String)
    history = db.Column(db.Integer)


    def __init__(self, email, token, refresh_token, token_uri, client_id, client_secret, scopes, history):
        self.email = email
        self.token = token
        self.refresh_token = refresh_token
        self.token_uri = token_uri
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.history = history


    def __repr__(self):
        return '<email {}, token {}, refresh_token {}, token_uri {}, client_id {}, client_secret {}, scopes {}, history {}>'.format(self.email, self.token, self.refresh_token, self.token_uri, self.client_id, self.client_secret, self.scopes, self.history)

