import flask
from flask import Flask, session, request, redirect, render_template, url_for

import pycurl
from io import BytesIO
import urllib
import json

import random
import os
from os import path, walk

from toy_oauth_server.database import init_db, db_session
from toy_oauth_server import models

app = Flask(__name__)

app.secret_key = os.urandom(28)

init_db()

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
            error_message = "User with email address "+request.form.get('email')+" does not exist or password is wrong"
            return redirect(url_for("signin", message = error_message),302)

        else:
            user = users[0]
            if (user.check_password(request.form.get('password'))):
                session['current_user_email'] = user.email
                return redirect(url_for("user_profile"),302)
                
            else:
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
                application.privacy_policy_url = request.form.get('privacy_policy_url')
                application.redirect_url = request.form.get('redirect_url')
                user.applications.append(application)


                db_session.add(user)
                db_session.commit()


                return redirect(url_for("user_profile", message = error_message),302)
    return "Only Post Method Supported"


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
            error_message = "invalid user session, please sign in again"
            return redirect(url_for("signin", message = error_message),302)



    return redirect(url_for("signin", message="User successfully logged out"),302)


@app.route('/logout')
def logout():
    session['current_user_email'] = None
    return redirect(url_for("signin", message="User successfully logged out"),302)

@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

@app.route('/test')
def test():
    return render_template('test.html')



@app.teardown_appcontext
def shutdown_session(execption = None):
    db_session.remove()




if __name__ == '__main__':
    app.run(extra_files=extra_files)



