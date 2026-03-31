import os
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base

_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test.db')
engine = create_engine(f'sqlite:///{_db_path}')
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    import toy_oauth_server.models
    Base.metadata.create_all(bind=engine)