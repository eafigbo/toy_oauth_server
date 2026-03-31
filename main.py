import flask
from flask import Flask, session, request, redirect, render_template, url_for, jsonify

import secrets
import urllib.parse
import base64
import time
import os
import logging
from datetime import datetime
from functools import wraps

from toy_oauth_server.database import init_db, db_session
from toy_oauth_server import models
from toy_oauth_server import jwt_utils

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

init_db()
jwt_utils.init_keys()

# ── Audit logging ─────────────────────────────────────────────────────────────

_audit_logger = logging.getLogger('audit')
_audit_logger.setLevel(logging.INFO)

_audit_fmt = logging.Formatter('%(asctime)s  %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

_ch = logging.StreamHandler()
_ch.setFormatter(_audit_fmt)
_audit_logger.addHandler(_ch)

_fh = logging.FileHandler(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit.log')
)
_fh.setFormatter(_audit_fmt)
_audit_logger.addHandler(_fh)


def _audit(event, **kwargs):
    """Write one audit log line: fixed-width event name followed by key=value pairs."""
    parts = '  '.join(f'{k}={v}' for k, v in kwargs.items())
    _audit_logger.info(f'{event:<26} {parts}')


# ── Promote a user to admin on startup if ADMIN_EMAIL is set ──────────────────
_admin_email = os.environ.get('ADMIN_EMAIL')
if _admin_email:
    _admin_user = db_session.query(models.User).filter_by(email=_admin_email).first()
    if _admin_user and not _admin_user.is_admin:
        _admin_user.is_admin = True
        db_session.commit()
    db_session.remove()


@app.context_processor
def inject_current_user():
    email = session.get('current_user_email')
    if email:
        return {'current_user': db_session.query(models.User).filter_by(email=email).first()}
    return {'current_user': None}


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        email = session.get('current_user_email')
        if not email:
            return redirect(url_for('signin', message='Please sign in to continue'))
        user = db_session.query(models.User).filter_by(email=email).first()
        if not user or not user.is_admin:
            return render_template('admin/forbidden.html'), 403
        return f(*args, **kwargs)
    return decorated


ISSUER_URL = os.environ.get('ISSUER_URL', 'http://localhost:5000')

# Scopes this server recognises.
# openid  — triggers ID token issuance (OIDC core)
# profile — name claims (given_name, family_name, name)
# email   — email claim
SUPPORTED_SCOPES = {'openid', 'profile', 'email'}

_BASIC_WWW_AUTH = {'WWW-Authenticate': 'Basic realm="Toy OAuth Server"'}


def _parse_client_credentials():
    """Return (client_id, client_secret) from Basic Auth header or POST body."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            client_id, client_secret = decoded.split(':', 1)
            return client_id, client_secret
        except Exception:
            return None, None
    return request.form.get('client_id'), request.form.get('client_secret')


def _verify_client():
    """Parse credentials and look up the Application. Returns (application, error_response)."""
    client_id, client_secret = _parse_client_credentials()
    application = db_session.query(models.Application).filter_by(
        client_id=client_id, client_secret=client_secret
    ).first()
    if not application:
        return None, (jsonify(error='invalid_client'), 401, _BASIC_WWW_AUTH)
    return application, None


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/register')
def register():
    message = request.args.get('message')
    return render_template('register.html', message = message)


@app.route('/signin')
def signin():
    message = request.args.get('message')
    #check for valid session
    current_user_email = session.get('current_user_email',None)
    if(current_user_email):
        return redirect(url_for("user_profile"),302)

    return render_template('signin.html', message = message)


@app.route('/registeruser', methods = ['POST'])
def register_user():
    if(request.method == 'POST'):
        error_message = ""
        users = db_session.query(models.User).filter(models.User.email == request.form.get('email'))
        if(users.count() == 0):
            user = models.User()
            user.first_name = request.form.get('first_name')
            user.last_name = request.form.get('last_name')
            user.email = request.form.get('email')
            user.address = request.form.get('home_address')
            print('address is '+ str(request.form.get('home_address')))

            print('password is '+ str(request.form.get('password')))
            user.set_password(request.form.get('password').strip())
            db_session.add(user)
            db_session.commit()
            _audit('USER_REGISTERED', email=user.email, ip=request.remote_addr)
        else:
            error_message = "User with email address "+request.form.get('email')+" already exists"
            print(error_message)
            return redirect(url_for("register", message = error_message),302)

        return render_template('user_registered.html', user=user)
    return "Only Post Method Supported"



@app.route('/signuserin', methods = ['POST'])
def sign_user_in():
    if(request.method == 'POST'):
        error_message = ""
        users = db_session.query(models.User).filter(models.User.email == request.form.get('email'))
        if(users.count() == 0):
            _audit('SIGN_IN_FAIL', email=request.form.get('email'), ip=request.remote_addr, reason='user_not_found')
            error_message = "User with email address "+request.form.get('email')+" does not exist or password is wrong"
            return redirect(url_for("signin", message = error_message),302)

        else:
            user = users[0]
            if (user.check_password(request.form.get('password'))):
                _audit('SIGN_IN_OK', email=user.email, ip=request.remote_addr)
                session['current_user_email'] = user.email
                next_url = session.pop('oauth_next', None)
                return redirect(next_url if next_url else url_for("user_profile"), 302)

            else:
                _audit('SIGN_IN_FAIL', email=user.email, ip=request.remote_addr, reason='wrong_password')
                error_message = "please enter valid user name or password"
                return redirect(url_for("signin", message = error_message),302)

    return "Only Post Method Supported"

@app.route('/add_application')
def add_application():
    message = request.args.get('message')
    return render_template('add_application.html', message = message)

@app.route('/save_application', methods = ['POST'])
def save_application():
    if(request.method == 'POST'):
        current_user_email = session.get('current_user_email',None)
        if(current_user_email ==  None):
            error_message = "Session expired, please sign in"
            return redirect(url_for("signin", message = error_message),302)
        else:
            users = db_session.query(models.User).filter(models.User.email == current_user_email)
            if(users.count() > 0):
                user=users[0]
                error_message = ""
                application = models.Application()
                application.application_name = request.form.get('application_name')
                application.description = request.form.get('description')
                application.redirect_url = request.form.get('redirect_url')
                application.icon_url = request.form.get('icon_url')
                application.home_page_url = request.form.get('home_page_url')
                application.privacy_policy_url = request.form.get('privacy_policy_url')
                user.applications.append(application)


                db_session.add(user)
                db_session.commit()


                return redirect(url_for("user_profile", message = error_message),302)
    return "Only Post Method Supported"


@app.route('/edit_application/<int:app_id>')
def edit_application(app_id):
    current_user_email = session.get('current_user_email')
    if not current_user_email:
        return redirect(url_for('signin', message='Session expired, please sign in'))
    user = db_session.query(models.User).filter_by(email=current_user_email).first()
    application = db_session.query(models.Application).filter_by(id=app_id, user_id=user.id).first()
    if not application:
        return redirect(url_for('user_profile'))
    return render_template('edit_application.html', application=application)


@app.route('/update_application/<int:app_id>', methods=['POST'])
def update_application(app_id):
    current_user_email = session.get('current_user_email')
    if not current_user_email:
        return redirect(url_for('signin', message='Session expired, please sign in'))
    user = db_session.query(models.User).filter_by(email=current_user_email).first()
    application = db_session.query(models.Application).filter_by(id=app_id, user_id=user.id).first()
    if not application:
        return redirect(url_for('user_profile'))
    application.application_name = request.form.get('application_name')
    application.description      = request.form.get('description')
    application.redirect_url     = request.form.get('redirect_url')
    application.icon_url         = request.form.get('icon_url')
    application.home_page_url    = request.form.get('home_page_url')
    application.privacy_policy_url = request.form.get('privacy_policy_url')
    db_session.commit()
    return redirect(url_for('user_profile'))


@app.route('/profile')
def user_profile():
    current_user_email = session.get('current_user_email',None)
    if(current_user_email ==  None):
        error_message = "Session expired, please sign in"
        return redirect(url_for("signin", message = error_message),302)
    else:
        users = db_session.query(models.User).filter(models.User.email == current_user_email)
        if(users.count() > 0):
            return render_template('user_profile.html',user=users[0])
        else:
            session.pop('current_user_email', None)
            return redirect(url_for("signin", message="invalid user session, please sign in again"), 302)



@app.route('/logout')
def logout():
    _audit('SIGN_OUT', email=session.get('current_user_email', 'unknown'), ip=request.remote_addr)
    session.pop('current_user_email', None)
    return redirect(url_for("signin", message="User successfully logged out"),302)

# ── OAuth 2.0 endpoints ──────────────────────────────────────────────────────

@app.route('/oauth/authorize', methods=['GET'])
def oauth_authorize():
    client_id    = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope        = request.args.get('scope', 'profile')
    state        = request.args.get('state', '')
    nonce        = request.args.get('nonce', '')

    # Validate client and redirect_uri first — if invalid, show error page (must NOT redirect)
    application = db_session.query(models.Application).filter_by(client_id=client_id).first()
    if not application:
        return jsonify(error='invalid_client'), 400

    if redirect_uri != application.redirect_url:
        return jsonify(error='invalid_redirect_uri'), 400

    # redirect_uri is now trusted — redirect with error for any other problem
    if response_type != 'code':
        params = urllib.parse.urlencode({'error': 'unsupported_response_type', 'state': state})
        return redirect(f'{redirect_uri}?{params}')

    requested_scopes = set(scope.split()) if scope else set()
    unsupported = requested_scopes - SUPPORTED_SCOPES
    if unsupported:
        params = urllib.parse.urlencode({
            'error': 'invalid_scope',
            'error_description': f'unsupported scope(s): {" ".join(unsupported)}',
            'state': state
        })
        return redirect(f'{redirect_uri}?{params}')

    current_user_email = session.get('current_user_email')
    if not current_user_email:
        session['oauth_next'] = request.url
        return redirect(url_for('signin', message='Please sign in to continue'))

    return render_template('consent.html',
                           application=application,
                           scope=scope,
                           state=state,
                           nonce=nonce,
                           redirect_uri=redirect_uri,
                           current_user_email=current_user_email)


@app.route('/oauth/authorize', methods=['POST'])
def oauth_authorize_post():
    client_id    = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    scope        = request.form.get('scope', 'profile')
    state        = request.form.get('state', '')
    nonce        = request.form.get('nonce') or None   # None if absent or empty

    if not request.form.get('approved'):
        _audit('CONSENT_DENIED', user=session.get('current_user_email'), client=client_id, scope=scope)
        params = urllib.parse.urlencode({'error': 'access_denied', 'state': state})
        return redirect(f'{redirect_uri}?{params}')

    current_user_email = session.get('current_user_email')
    if not current_user_email:
        return redirect(url_for('signin'))

    user = db_session.query(models.User).filter_by(email=current_user_email).first()
    if not user:
        return redirect(url_for('signin'))

    auth_code = models.AuthorizationCode.create(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        user_id=user.id,
        nonce=nonce
    )
    db_session.add(auth_code)
    db_session.commit()
    _audit('CODE_ISSUED', user=user.email, client=client_id, scope=scope)

    params = urllib.parse.urlencode({'code': auth_code.code, 'state': state})
    return redirect(f'{redirect_uri}?{params}')


@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    application, err = _verify_client()
    if err:
        return err

    grant_type = request.form.get('grant_type')

    if grant_type == 'authorization_code':
        code         = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')

        auth_code = db_session.query(models.AuthorizationCode).filter_by(
            code=code, client_id=application.client_id
        ).first()
        if not auth_code:
            return jsonify(error='invalid_grant'), 400

        if auth_code.is_expired():
            db_session.delete(auth_code)
            db_session.commit()
            return jsonify(error='invalid_grant', error_description='code expired'), 400

        if auth_code.redirect_uri != redirect_uri:
            return jsonify(error='invalid_grant'), 400

        user_id = auth_code.user_id
        scope   = auth_code.scope
        nonce   = auth_code.nonce   # read before the row is deleted
        db_session.delete(auth_code)

        token = models.AccessToken.create(
            client_id=application.client_id, scope=scope, user_id=user_id
        )
        db_session.add(token)
        db_session.commit()
        _audit('TOKEN_ISSUED', grant='authorization_code', user=user_id, client=application.client_id, scope=scope)

        response = dict(
            access_token=token.access_token,
            token_type='Bearer',
            expires_in=3600,
            refresh_token=token.refresh_token,
            scope=scope,
        )

        # If the openid scope was granted, add a signed ID token (OIDC core).
        if 'openid' in set(scope.split()):
            user = db_session.query(models.User).filter_by(id=user_id).first()
            now  = int(time.time())

            id_token_payload = {
                'iss': ISSUER_URL,           # who issued this token
                'sub': str(user.id),         # who this token is about (stable identifier)
                'aud': application.client_id,# who this token is intended for
                'exp': now + 3600,           # expiry — same window as access token
                'iat': now,                  # issued at
                'auth_time': now,            # when the user actually authenticated
            }

            # nonce binds the ID token to this specific authorisation request;
            # the client compares it against the value it sent to detect replay attacks
            if nonce:
                id_token_payload['nonce'] = nonce

            # profile scope → name claims
            if 'profile' in set(scope.split()):
                id_token_payload['given_name']  = user.first_name
                id_token_payload['family_name'] = user.last_name
                id_token_payload['name']        = f'{user.first_name} {user.last_name}'

            # email scope → email claim
            if 'email' in set(scope.split()):
                id_token_payload['email'] = user.email

            response['id_token'] = jwt_utils.create_jwt(
                id_token_payload,
                jwt_utils.get_private_key(),
                jwt_utils.get_kid(),
            )
            _audit('ID_TOKEN_ISSUED', user=user.email, client=application.client_id, scope=scope)

        return jsonify(**response)

    elif grant_type == 'refresh_token':
        refresh_token_value = request.form.get('refresh_token')
        requested_scope     = request.form.get('scope')

        old_token = db_session.query(models.AccessToken).filter_by(
            refresh_token=refresh_token_value, client_id=application.client_id, is_active=True
        ).first()
        if not old_token:
            return jsonify(error='invalid_grant'), 400

        if old_token.is_refresh_token_expired():
            old_token.is_active = False
            db_session.commit()
            return jsonify(error='invalid_grant', error_description='refresh token expired'), 400

        # Requested scope must be equal to or a subset of the originally granted scope
        granted_scopes = set(old_token.scope.split())
        if requested_scope:
            new_scopes = set(requested_scope.split())
            if not new_scopes.issubset(granted_scopes):
                return jsonify(error='invalid_scope'), 400
            scope = requested_scope
        else:
            scope = old_token.scope

        user_id = old_token.user_id

        # Rotate: mark old token inactive, issue new one
        old_token.is_active = False
        token = models.AccessToken.create(
            client_id=application.client_id, scope=scope, user_id=user_id
        )
        db_session.add(token)
        db_session.commit()
        _audit('TOKEN_REFRESHED', user=user_id, client=application.client_id, scope=scope)

        return jsonify(
            access_token=token.access_token,
            token_type='Bearer',
            expires_in=3600,
            refresh_token=token.refresh_token,
            scope=scope
        )

    elif grant_type == 'urn:ietf:params:oauth:grant-type:token-exchange':
        # ── RFC 8693 Token Exchange ───────────────────────────────────────────
        #
        # The client presents a token it already holds (the subject_token) and
        # asks this server to issue a different kind of token in return.
        # All parameter names come directly from RFC 8693 §2.1.

        subject_token        = request.form.get('subject_token')
        subject_token_type   = request.form.get('subject_token_type')
        requested_token_type = request.form.get('requested_token_type')
        audience             = request.form.get('audience', '')
        scope                = request.form.get('scope', 'profile')

        # subject_token and subject_token_type are REQUIRED (RFC 8693 §2.1)
        if not subject_token or not subject_token_type:
            return jsonify(
                error='invalid_request',
                error_description='subject_token and subject_token_type are required',
            ), 400

        # requested_token_type is REQUIRED for this server
        if not requested_token_type:
            return jsonify(
                error='invalid_request',
                error_description='requested_token_type is required',
            ), 400

        # This server only accepts ID tokens as the input credential.
        # Future extensions could accept SAML assertions or refresh tokens here.
        if subject_token_type != 'urn:ietf:params:oauth:token-type:id_token':
            return jsonify(
                error='invalid_request',
                error_description='unsupported subject_token_type — only id_token is accepted',
            ), 400

        # Validate the scope being requested
        requested_scopes = set(scope.split()) if scope else set()
        unsupported = requested_scopes - SUPPORTED_SCOPES
        if unsupported:
            return jsonify(
                error='invalid_scope',
                error_description=f'unsupported scope(s): {" ".join(unsupported)}',
            ), 400

        # ── Verify the subject token ──────────────────────────────────────────
        # verify_jwt checks the RSA signature and the exp claim.
        # We then check iss and aud manually so the logic is explicit.
        try:
            claims = jwt_utils.verify_jwt(subject_token, jwt_utils.get_public_key())
        except ValueError as exc:
            return jsonify(error='invalid_grant', error_description=str(exc)), 400

        # iss must be this server — we only accept tokens we issued ourselves
        if claims.get('iss') != ISSUER_URL:
            return jsonify(
                error='invalid_grant',
                error_description='subject_token issuer does not match this server',
            ), 400

        # aud must be the requesting client — prevents a client from presenting
        # a token that was issued to a different client (confused deputy)
        if claims.get('aud') != application.client_id:
            return jsonify(
                error='invalid_grant',
                error_description='subject_token audience does not match client_id',
            ), 400

        # Look up the user identified by the sub claim
        try:
            user = db_session.query(models.User).filter_by(id=int(claims['sub'])).first()
        except (ValueError, KeyError):
            user = None
        if not user:
            return jsonify(
                error='invalid_grant',
                error_description='subject identified by sub claim not found',
            ), 400

        _audit('TOKEN_EXCHANGED', user=claims['sub'], client=application.client_id,
               subject_type='id_token', requested=requested_token_type)

        # ── Route on requested_token_type ────────────────────────────────────

        if requested_token_type == 'urn:ietf:params:oauth:token-type:id-jag':
            # Identity Assertion JWT Authorization Grant
            # (draft-ietf-oauth-identity-assertion-authz-grant)
            #
            # The ID-JAG is a short-lived signed JWT that the client can present
            # to a Resource Authorization Server (RAS) in a different trust domain.
            # The RAS verifies the signature using our JWKS endpoint and, if valid,
            # issues its own access token for the resource — without requiring the
            # user to interactively approve again.

            # audience identifies the target RAS and becomes the aud claim.
            # It is required: the aud claim is what prevents an ID-JAG issued for
            # one RAS from being replayed against a different one.
            if not audience:
                return jsonify(
                    error='invalid_request',
                    error_description='audience is required for id-jag token type',
                ), 400

            # ── Policy check ─────────────────────────────────────────────────
            # The audience must be a ResourceServer registered with this IdP,
            # and this client must be explicitly granted access to it.
            # Without this check any registered client could obtain an ID-JAG
            # for any audience URI — the IdP would have no control over
            # cross-domain delegations.

            resource_server = db_session.query(models.ResourceServer).filter_by(
                uri=audience
            ).first()
            if not resource_server:
                return jsonify(
                    error='invalid_target',
                    error_description='audience is not a registered resource server',
                ), 400

            access_grant = db_session.query(models.ClientResourceAccess).filter_by(
                application_id=application.id,
                resource_server_id=resource_server.id,
            ).first()
            if not access_grant:
                _audit('POLICY_DENIED', user=claims['sub'], client=application.client_id, audience=audience)
                return jsonify(
                    error='unauthorized_client',
                    error_description='this client is not authorised to access the requested audience',
                ), 403

            now = int(time.time())

            id_jag_payload = {
                'iss':       ISSUER_URL,             # this server issued the JAG
                'sub':       claims['sub'],           # the user being delegated
                'aud':       audience,               # the RAS that will accept it
                'client_id': application.client_id,  # the client making the request
                'jti':       secrets.token_urlsafe(16),  # unique ID — replay protection
                'exp':       now + 300,              # 5 minutes: short-lived by design
                'iat':       now,
                'scope':     scope,
            }

            id_jag = jwt_utils.create_jwt(
                id_jag_payload,
                jwt_utils.get_private_key(),
                jwt_utils.get_kid(),
            )

            _audit('ID_JAG_ISSUED', user=claims['sub'], client=application.client_id,
                   audience=audience, scope=scope)

            # RFC 8693 §2.2 response.
            # token_type is N_A (not applicable) — the ID-JAG is NOT a Bearer token.
            # It is a credential to be exchanged at the RAS, not used directly.
            return jsonify(
                access_token=id_jag,
                issued_token_type='urn:ietf:params:oauth:token-type:id-jag',
                token_type='N_A',
                expires_in=300,
            )

        return jsonify(
            error='invalid_request',
            error_description=f'unsupported requested_token_type: {requested_token_type}',
        ), 400

    return jsonify(error='unsupported_grant_type'), 400


@app.route('/oauth/userinfo')
def oauth_userinfo():
    _bearer_header = {'WWW-Authenticate': 'Bearer realm="Toy OAuth Server"'}
    _invalid_token = {'WWW-Authenticate':
                      'Bearer realm="Toy OAuth Server", error="invalid_token"'}

    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify(error='invalid_token'), 401, _bearer_header

    token_value = auth_header[len('Bearer '):]
    token = db_session.query(models.AccessToken).filter_by(access_token=token_value).first()
    if not token or not token.is_valid():
        _audit('TOKEN_REJECTED', endpoint='userinfo', ip=request.remote_addr)
        return jsonify(error='invalid_token'), 401, _invalid_token

    user           = db_session.query(models.User).filter_by(id=token.user_id).first()
    granted_scopes = set(token.scope.split())

    # sub is the OIDC standard primary identifier — always included
    claims = {'sub': str(user.id)}

    if 'profile' in granted_scopes:
        claims['given_name']  = user.first_name
        claims['family_name'] = user.last_name
        claims['name']        = f'{user.first_name} {user.last_name}'

    if 'email' in granted_scopes or 'openid' in granted_scopes:
        claims['email'] = user.email

    return jsonify(**claims)


@app.route('/oauth/introspect', methods=['POST'])
def oauth_introspect():
    application, err = _verify_client()
    if err:
        return err

    token_value     = request.form.get('token')
    token_type_hint = request.form.get('token_type_hint', 'access_token')

    # Search by hint first, then fall back to the other field
    if token_type_hint == 'refresh_token':
        token = (db_session.query(models.AccessToken).filter_by(refresh_token=token_value).first()
                 or db_session.query(models.AccessToken).filter_by(access_token=token_value).first())
    else:
        token = (db_session.query(models.AccessToken).filter_by(access_token=token_value).first()
                 or db_session.query(models.AccessToken).filter_by(refresh_token=token_value).first())

    if not token or not token.is_valid():
        return jsonify(active=False)

    user = db_session.query(models.User).filter_by(id=token.user_id).first()
    return jsonify(
        active=True,
        scope=token.scope,
        client_id=token.client_id,
        username=user.email,
        token_type='Bearer',
        exp=int(token.expires_at.timestamp()),
        sub=str(token.user_id)
    )


@app.route('/oauth/revoke', methods=['POST'])
def oauth_revoke():
    application, err = _verify_client()
    if err:
        return err

    token_value = request.form.get('token')

    token = (db_session.query(models.AccessToken).filter_by(access_token=token_value).first()
             or db_session.query(models.AccessToken).filter_by(refresh_token=token_value).first())

    if token:
        token.is_active = False
        db_session.commit()
        _audit('TOKEN_REVOKED', client=application.client_id, user=token.user_id)

    # RFC 7009 §2.2 — always return 200, even if the token was not found
    return '', 200


# ── OIDC discovery endpoints ─────────────────────────────────────────────────
#
# These two routes are designed to be fetched by external Resource Authorization
# Servers so they can discover this server's configuration and public keys.
# Unlike every other endpoint, their responses are safe to cache.

@app.route('/.well-known/openid-configuration')
def openid_configuration():
    """
    OIDC Discovery Document (RFC 8414 / OpenID Connect Discovery 1.0).

    A machine-readable description of this server's capabilities and endpoints.
    An RAS fetches this URL to find the jwks_uri, then fetches the JWKS to get
    the public key needed to verify ID tokens and ID-JAGs.
    """
    return jsonify({
        'issuer':                                ISSUER_URL,
        'authorization_endpoint':               f'{ISSUER_URL}/oauth/authorize',
        'token_endpoint':                        f'{ISSUER_URL}/oauth/token',
        'userinfo_endpoint':                     f'{ISSUER_URL}/oauth/userinfo',
        'jwks_uri':                              f'{ISSUER_URL}/.well-known/jwks.json',
        'introspection_endpoint':                f'{ISSUER_URL}/oauth/introspect',
        'revocation_endpoint':                   f'{ISSUER_URL}/oauth/revoke',
        'scopes_supported':                      sorted(SUPPORTED_SCOPES),
        'response_types_supported':              ['code'],
        'subject_types_supported':               ['public'],
        'id_token_signing_alg_values_supported': ['RS256'],
        'token_endpoint_auth_methods_supported': [
            'client_secret_basic',
            'client_secret_post',
        ],
        'grant_types_supported': [
            'authorization_code',
            'refresh_token',
            'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        'claims_supported': [
            'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce',
            'name', 'given_name', 'family_name', 'email',
        ],
    })


@app.route('/.well-known/jwks.json')
def jwks():
    """
    JSON Web Key Set (RFC 7517).

    Exposes the RSA public key so that any party that receives a JWT signed
    by this server can verify its signature without contacting this server again.

    The key is wrapped in a 'keys' array so additional keys can be added
    during rotation without breaking clients that have cached the document.
    """
    return jsonify({'keys': [jwt_utils.get_jwks()]})


# ── Admin endpoints ──────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_dashboard():
    user_count   = db_session.query(models.User).count()
    app_count    = db_session.query(models.Application).count()
    token_count  = db_session.query(models.AccessToken).filter_by(is_active=True).count()
    server_count = db_session.query(models.ResourceServer).count()
    return render_template('admin/dashboard.html',
                           user_count=user_count,
                           app_count=app_count,
                           token_count=token_count,
                           server_count=server_count)


@app.route('/admin/users')
@admin_required
def admin_users():
    users = db_session.query(models.User).order_by(models.User.id).all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/new')
@admin_required
def admin_user_new():
    return render_template('admin/user_form.html', user=None,
                           action='/admin/users/create', error=None)


@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_user_create():
    email = request.form.get('email', '').strip()
    if db_session.query(models.User).filter_by(email=email).first():
        return render_template('admin/user_form.html', user=None,
                               action='/admin/users/create',
                               error=f'A user with email {email} already exists'), 400
    user = models.User()
    user.first_name = request.form.get('first_name')
    user.last_name  = request.form.get('last_name')
    user.email      = email
    user.address    = request.form.get('address')
    user.is_admin   = bool(request.form.get('is_admin'))
    user.set_password(request.form.get('password'))
    db_session.add(user)
    db_session.commit()
    _audit('ADMIN_USER_CREATED', admin=session.get('current_user_email'), new_user=email)
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/edit')
@admin_required
def admin_user_edit(user_id):
    user = db_session.query(models.User).filter_by(id=user_id).first()
    if not user:
        return redirect(url_for('admin_users'))
    return render_template('admin/user_form.html', user=user,
                           action=f'/admin/users/{user_id}/update', error=None)


@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@admin_required
def admin_user_update(user_id):
    user = db_session.query(models.User).filter_by(id=user_id).first()
    if not user:
        return redirect(url_for('admin_users'))
    user.first_name = request.form.get('first_name')
    user.last_name  = request.form.get('last_name')
    user.email      = request.form.get('email', '').strip()
    user.address    = request.form.get('address')
    user.is_admin   = bool(request.form.get('is_admin'))
    new_password    = request.form.get('password')
    if new_password:
        user.set_password(new_password)
    db_session.commit()
    _audit('ADMIN_USER_UPDATED', admin=session.get('current_user_email'), target=user.email)
    return redirect(url_for('admin_users'))


@app.route('/admin/applications')
@admin_required
def admin_applications():
    apps = db_session.query(models.Application).order_by(models.Application.id).all()
    return render_template('admin/applications.html', applications=apps)


@app.route('/admin/applications/<int:app_id>/edit')
@admin_required
def admin_application_edit(app_id):
    application = db_session.query(models.Application).filter_by(id=app_id).first()
    if not application:
        return redirect(url_for('admin_applications'))
    return render_template('admin/application_form.html', application=application)


@app.route('/admin/applications/<int:app_id>/update', methods=['POST'])
@admin_required
def admin_application_update(app_id):
    application = db_session.query(models.Application).filter_by(id=app_id).first()
    if not application:
        return redirect(url_for('admin_applications'))
    application.application_name    = request.form.get('application_name')
    application.description         = request.form.get('description')
    application.redirect_url        = request.form.get('redirect_url')
    application.icon_url            = request.form.get('icon_url')
    application.home_page_url       = request.form.get('home_page_url')
    application.privacy_policy_url  = request.form.get('privacy_policy_url')
    db_session.commit()
    return redirect(url_for('admin_applications'))


@app.route('/admin/resource_servers')
@admin_required
def admin_resource_servers():
    servers = db_session.query(models.ResourceServer).order_by(models.ResourceServer.id).all()
    return render_template('admin/resource_servers.html', servers=servers)


@app.route('/admin/resource_servers/new')
@admin_required
def admin_resource_server_new():
    return render_template('admin/resource_server_form.html', server=None,
                           action='/admin/resource_servers/create', error=None)


@app.route('/admin/resource_servers/create', methods=['POST'])
@admin_required
def admin_resource_server_create():
    uri = request.form.get('uri', '').strip()
    if db_session.query(models.ResourceServer).filter_by(uri=uri).first():
        return render_template('admin/resource_server_form.html', server=None,
                               action='/admin/resource_servers/create',
                               error=f'A resource server with URI {uri} already exists'), 400
    server = models.ResourceServer()
    server.name        = request.form.get('name')
    server.uri         = uri
    server.description = request.form.get('description')
    db_session.add(server)
    db_session.commit()
    _audit('ADMIN_RS_CREATED', admin=session.get('current_user_email'), uri=server.uri)
    # Go straight to edit so the admin can add client mappings immediately
    return redirect(url_for('admin_resource_server_edit', server_id=server.id))


@app.route('/admin/resource_servers/<int:server_id>/edit')
@admin_required
def admin_resource_server_edit(server_id):
    server = db_session.query(models.ResourceServer).filter_by(id=server_id).first()
    if not server:
        return redirect(url_for('admin_resource_servers'))
    all_apps     = db_session.query(models.Application).order_by(models.Application.id).all()
    granted_ids  = {a.application_id for a in server.client_access}
    available_apps = [a for a in all_apps if a.id not in granted_ids]
    return render_template('admin/resource_server_form.html', server=server,
                           action=f'/admin/resource_servers/{server_id}/update',
                           available_apps=available_apps, error=None)


@app.route('/admin/resource_servers/<int:server_id>/update', methods=['POST'])
@admin_required
def admin_resource_server_update(server_id):
    server = db_session.query(models.ResourceServer).filter_by(id=server_id).first()
    if not server:
        return redirect(url_for('admin_resource_servers'))
    server.name        = request.form.get('name')
    server.uri         = request.form.get('uri', '').strip()
    server.description = request.form.get('description')
    db_session.commit()
    return redirect(url_for('admin_resource_server_edit', server_id=server_id))


@app.route('/admin/resource_servers/<int:server_id>/grant', methods=['POST'])
@admin_required
def admin_resource_server_grant(server_id):
    server = db_session.query(models.ResourceServer).filter_by(id=server_id).first()
    if not server:
        return redirect(url_for('admin_resource_servers'))
    app_id = request.form.get('application_id', type=int)
    exists = db_session.query(models.ClientResourceAccess).filter_by(
        application_id=app_id, resource_server_id=server_id
    ).first()
    if not exists:
        access = models.ClientResourceAccess()
        access.application_id     = app_id
        access.resource_server_id = server_id
        db_session.add(access)
        db_session.commit()
        granted_app = db_session.query(models.Application).filter_by(id=app_id).first()
        _audit('ADMIN_ACCESS_GRANTED', admin=session.get('current_user_email'),
               client=granted_app.client_id if granted_app else app_id, rs=server.uri)
    return redirect(url_for('admin_resource_server_edit', server_id=server_id))


@app.route('/admin/resource_servers/<int:server_id>/revoke/<int:app_id>', methods=['POST'])
@admin_required
def admin_resource_server_revoke(server_id, app_id):
    access = db_session.query(models.ClientResourceAccess).filter_by(
        application_id=app_id, resource_server_id=server_id
    ).first()
    if access:
        _audit('ADMIN_ACCESS_REVOKED', admin=session.get('current_user_email'),
               client=access.application.client_id, rs=access.resource_server.uri)
        db_session.delete(access)
        db_session.commit()
    return redirect(url_for('admin_resource_server_edit', server_id=server_id))


# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def add_header(r):
    # The discovery document and JWKS are public, read-only, and designed to be
    # cached by clients (RAS servers, libraries).  Every other response must not
    # be cached — tokens, user data, and auth codes must never be stored by proxies.
    if request.path in ('/.well-known/openid-configuration', '/.well-known/jwks.json'):
        r.headers['Cache-Control'] = 'public, max-age=3600'
        return r
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

@app.route('/test')
def test():
    return render_template('test.html')



@app.teardown_appcontext
def shutdown_session(execption = None):
    db_session.remove()




if __name__ == '__main__':
    app.run(extra_files=extra_files)



