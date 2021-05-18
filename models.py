from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
import secrets
from toy_oauth_server.database import Base



class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key = True)
    first_name = Column(String(50))
    last_name = Column(String(50))
    email = Column(String(120), unique = True)
    address = Column(String(200))
    password_hash = Column(String(200))

    applications = relationship('Application', order_by='Application.id', back_populates='user')


    def __repr__(self):
        return "{User(first name ='%s', last name = '%s', email = '%s')}" % (self.first_name, self.last_name, self.email)

    def set_password(self, raw_password):
        import random
        algo = 'sha1'
        salt=self.get_hexdigest(algo,str(random.random()), str(random.random()))[:5]
        hsh = self.get_hexdigest(algo,salt, raw_password)
        self.password_hash ='%s$%s$%s' % (algo, salt, hsh)

    def get_hexdigest(self,algo,salt, to_hash):
        import hashlib
        return hashlib.sha1(('%s%s' % (salt, to_hash)).encode('utf-8')).hexdigest()

    def check_password(self,raw_password):
        """ returns a boolean of whether the raw_password was correct. 
        Handles encryption formats behind the scenes
        """
        algo, salt, hsh = self.password_hash.split('$')
        return hsh == self.get_hexdigest(algo, salt ,raw_password)

    
class Application(Base):
    __tablename__ = 'application'
    id = Column(Integer, primary_key = True)
    application_name = Column(String(50))
    icon_url = Column(String(200))
    home_page_url = Column(String(200))
    description = Column(String(400))
    privacy_policy_url = Column(String(200))
    client_id = Column(String(50),nullable = False, unique = True, default = secrets.token_hex(16) )
    client_secret = Column(String(50),nullable = False,default = secrets.token_hex(32))
    redirect_url = Column(String(200))
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship('User', back_populates='applications')

    def __repr__(self):
        return "{Application(application_name ='%s')}" % self.application_name


    


