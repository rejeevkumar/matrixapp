from flask import Flask, redirect, url_for, session, request
from flask_oauthlib.client import OAuth
from azure.identity import DefaultAzureCredential

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this to a secure random value

# Azure AD credentials
client_id = "your_client_id"
tenant_id = "your_tenant_id"
authority = f"https://login.microsoftonline.com/{tenant_id}"

# OAuth configuration
oauth = OAuth(app)
azure = oauth.remote_app(
    "azure",
    consumer_key=client_id,
    request_token_params={"scope": "openid email profile"},
    base_url=None,
    request_token_url=None,
    access_token_method="POST",
    access_token_url=f"{authority}/oauth2/token",
    authorize_url=f"{authority}/oauth2/authorize",
)

# Routes
@app.route("/")
def index():
    return "Welcome to Azure AD SSO with Python Flask!"

@app.route("/login")
def login():
    return azure.authorize(callback=url_for("authorized", _external=True))

@app.route("/login/callback")
def authorized():
    response = azure.authorized_response()
    if response is None or response.get("access_token") is None:
        return "Access denied: reason={}&error={}".format(
            request.args["error_reason"], request.args["error_description"]
        )
    session["azure_token"] = (response["access_token"], "")
    return redirect(url_for("profile"))

@app.route("/profile")
def profile():
    if "azure_token" in session:
        azure_token = session["azure_token"]
        return f"Logged in as {azure_token[1]}"
    return "Not logged in."

@azure.tokengetter
def get_azure_oauth_token():
    return session.get("azure_token")

if __name__ == "__main__":
    app.run(ssl_context="adhoc", port=5000)  # Use SSL for production deployment
