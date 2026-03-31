from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
import secrets
import hashlib
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from toy_oauth_server.database import Base



class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key = True)
    first_name = Column(String(50))
    last_name = Column(String(50))
    email = Column(String(120), unique = True)
    address = Column(String(200))
    password_hash = Column(String(200))
    is_admin = Column(Boolean, default=False, nullable=False)

    applications = relationship('Application', order_by='Application.id', back_populates='user')


    def __repr__(self):
        return "{User(first name ='%s', last name = '%s', email = '%s')}" % (self.first_name, self.last_name, self.email)

    def set_password(self, raw_password):
        method = 'scrypt' if hasattr(hashlib, 'scrypt') else 'pbkdf2:sha256'
        self.password_hash = generate_password_hash(raw_password, method=method)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    
class Application(Base):
    __tablename__ = 'application'
    id = Column(Integer, primary_key = True)
    application_name = Column(String(50))
    icon_url = Column(String(200))
    home_page_url = Column(String(200))
    description = Column(String(400))
    privacy_policy_url = Column(String(200))
    client_id = Column(String(50), nullable=False, unique=True, default=lambda: secrets.token_hex(16))
    client_secret = Column(String(50), nullable=False, default=lambda: secrets.token_hex(32))
    redirect_url = Column(String(200))
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship('User', back_populates='applications')
    resource_access = relationship('ClientResourceAccess', back_populates='application',
                                   cascade='all, delete-orphan')

    def __repr__(self):
        return "{Application(application_name ='%s')}" % self.application_name


class AuthorizationCode(Base):
    __tablename__ = 'authorization_codes'
    id = Column(Integer, primary_key=True)
    code = Column(String(128), unique=True, nullable=False)
    client_id = Column(String(50), nullable=False)
    redirect_uri = Column(String(200), nullable=False)
    scope = Column(String(200), default='profile')
    state = Column(String(200))
    nonce = Column(String(200), nullable=True)   # OIDC replay protection
    expires_at = Column(DateTime, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    user = relationship('User')

    @staticmethod
    def create(client_id, redirect_uri, scope, state, user_id, nonce=None):
        code = AuthorizationCode()
        code.code = secrets.token_urlsafe(32)
        code.client_id = client_id
        code.redirect_uri = redirect_uri
        code.scope = scope
        code.state = state
        code.nonce = nonce
        code.expires_at = datetime.utcnow() + timedelta(minutes=10)
        code.user_id = user_id
        return code

    def is_expired(self):
        return datetime.utcnow() > self.expires_at


class AccessToken(Base):
    __tablename__ = 'access_tokens'
    id = Column(Integer, primary_key=True)
    access_token = Column(String(128), unique=True, nullable=False)
    token_type = Column(String(20), default='Bearer')
    scope = Column(String(200), default='profile')
    expires_at = Column(DateTime, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    client_id = Column(String(50), nullable=False)
    refresh_token = Column(String(128), unique=True, nullable=False)
    refresh_token_expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    user = relationship('User')

    @staticmethod
    def create(client_id, scope, user_id):
        token = AccessToken()
        token.access_token = secrets.token_urlsafe(48)
        token.token_type = 'Bearer'
        token.scope = scope
        token.expires_at = datetime.utcnow() + timedelta(hours=1)
        token.user_id = user_id
        token.client_id = client_id
        token.refresh_token = secrets.token_urlsafe(48)
        token.refresh_token_expires_at = datetime.utcnow() + timedelta(days=30)
        token.is_active = True
        return token

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def is_refresh_token_expired(self):
        return datetime.utcnow() > self.refresh_token_expires_at

    def is_valid(self):
        return self.is_active and not self.is_expired()


class ResourceServer(Base):
    """
    A Resource Authorization Server registered with this IdP.

    The uri is the audience value that clients must supply when requesting
    an ID-JAG targeting this server.  Only resource servers registered here
    are eligible to receive ID-JAGs from this IdP.
    """
    __tablename__ = 'resource_servers'
    id          = Column(Integer, primary_key=True)
    name        = Column(String(100), nullable=False)
    uri         = Column(String(200), nullable=False, unique=True)
    description = Column(String(400))

    client_access = relationship('ClientResourceAccess', back_populates='resource_server',
                                  cascade='all, delete-orphan')


class ClientResourceAccess(Base):
    """
    Policy mapping: which client applications are authorised to obtain
    ID-JAGs for which resource servers.

    The IdP checks this table during token exchange and rejects requests
    where no matching row exists (RFC 8693 / ID-JAG Security Considerations).
    """
    __tablename__ = 'client_resource_access'
    __table_args__ = (
        UniqueConstraint('application_id', 'resource_server_id',
                         name='uq_client_resource'),
    )
    id                 = Column(Integer, primary_key=True)
    application_id     = Column(Integer, ForeignKey('application.id'),    nullable=False)
    resource_server_id = Column(Integer, ForeignKey('resource_servers.id'), nullable=False)

    application     = relationship('Application',    back_populates='resource_access')
    resource_server = relationship('ResourceServer', back_populates='client_access')

