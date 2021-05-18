#! python3

from database import init_db
from database import db_session
import models
import secrets

init_db()



def test_user_and_application():
    u = models.User(first_name = 'Emeska',last_name= 'Afigbo',email= secrets.token_hex(2)+'@ems.com',address= 'Emeka Street, Emeka Town')

    u.set_password('this is a test')

    db_session.add(u)
    db_session.commit()

    print(str(u) + 'added')

    print(str('checking password: this is a test')+str(u.check_password('this is a test')))
    print(str('checking password: this is not a test')+str(u.check_password('this is not a test')))

    a = models.Application()

    a.application_name = 'Test application'
    a.icon_url = 'iconurl.com/icon'
    a.home_page_url = 'homepageurl.com/url'
    a.description = 'Test description'
    a.privacy_policy_url = 'privacyurl.com/url'
    #a.client_id = 'testid'
    #a.client_secret = 'test secret'
    a.redirect_url = 'redirect.com/url'

    u.applications.append(a)
    db_session.commit()

 

    print('Created application '+str(a))
    print('Application ' +str(a) +' \n now added to\n '+str(u))



#test_application()
test_user_and_application()