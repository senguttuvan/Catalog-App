from flask import (Flask, render_template,
                   request, redirect,
                   jsonify, url_for)
from flask import make_response, flash
from flask import session as login_session
from functools import wraps

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from model import Base, User, Category, Item

import httplib2
import json
import requests
import random
import string


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

app = Flask(__name__)

APPLICATION_NAME = "Item Catalog Web Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # For DEBUG:
    # login_session['username'] = 'nsengutt'
    # login_session['user_id'] = 'asgd'
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and \
            gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is '
                                            'already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    # login_session['access_token'] = credentials.access_token
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    # params = {'access_token': credentials.access_token, 'alt': 'json'}
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px' \
              ';-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Succesfully logged in as %s" % login_session['username'])
    return output


def createUser(login_session):
    """
    Creates a new user in the database
    :param
        login_session: session object with user data

    :return:
        user.id: generated distinct integer value identifying the newly
        created user
    """

    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    Gets user object from user_id
    :param user_id
    :return: user : User object
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    Get User id from user email
    :param email: user email
    :return: user.id
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# For DEBUG Need to uncomment
@app.route('/gdisconnect')
def gdisconnect():
    """
    Sign out from the Google Account and delete user info
    from the login session
    """
    access_token = login_session.get('access_token')

    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()

    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        # del login_session['user_id']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Successfully logged out")
        return redirect('/')
        # return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# For DEBUG
# @app.route('/gdisconnect')
# def gdisconnect():
#     del login_session['username']
#     return redirect('/')


def login_required(f):
    """
    Decorator function that checks if user is logged in
    :param f: input function
    :return: decorated function
           Redirects to Login page when user is not signed in
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("here hereh ere")
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("LOGIN REQUIRED !!")
            return redirect('/login')
    return decorated_function


@app.route('/')
def showCatalog():
    """ Home page that shows all categories in the catalog"""
    categories = session.query(Category).all()
    return render_template('catalog.html', categorys=categories)


@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
    Create a new Category in the database
    Returns:
        on GET: Page to Create a new Category
        on POST: Redirect to main page after Category has been created.
        Login page when user is not signed in
    """

    user_id = login_session['user_id']

    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=user_id)
        session.add(newCategory)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newcategory.html')


# Edit Category
@app.route('/catalog/<category_name>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    """
    Edit Category in the database
    Args : Category name
    Returns:
        on GET: Page to Edit Category
        on POST: Redirect to main page after Category has been edited.
        Home page if not authorized to make change
    """

    editedCategory = session.query(Category).\
        filter_by(name=category_name).one()

    if editedCategory.user_id != login_session['user_id']:
        flash('WARNING ! Permission denied')
        return redirect(url_for('showCatalog'))

    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            return redirect(url_for('showCatalog'))
    else:
        return render_template('editcategory.html', category=editedCategory)


# Delete Category
@app.route('/catalog/<category_name>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    """
    Delete Category in the database
    Args : Category name
    Returns:
        on GET: Page to Delete Category
        on POST: Redirect to main page after Category has been deleted
        Shows warning and redirects to Home page if not authorized
        to make changes
    """

    category = session.query(Category).filter_by(name=category_name).one()

    if category.user_id != login_session['user_id']:
        flash('WARNING ! Permission denied')
        return redirect(url_for('showCatalog'))

    if request.method == 'POST':
        session.delete(category)
        session.commit()

        return redirect(url_for('showCatalog'))
    else:
        return render_template('deletecategory.html', category=category)


@app.route('/category/<category_name>/')
@app.route('/catalog/<category_name>/items/')
def showItem(category_name):
    """
    Shows all items in the category
    Args: Category name
    Return : Redirect to Category page Show all Items
             for the Category
    """
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(
        category=category).all()
    return render_template('item.html', items=items,
                           category=category, categorys=categories)


@app.route('/catalog/<category_name>/item/new', methods=['GET', 'POST'])
@login_required
def newItem(category_name):
    """
    Create a new Item in the database
    Args : Category name
    Returns:
        on GET: Page to Create Item
        on POST: Redirect to Category page after Item has been created
    """

    user_id = login_session['user_id']

    category = session.query(Category).filter_by(name=category_name).one()

    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category.id,
                       user_id=user_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('newitem.html', category_name=category_name)


@app.route('/catalog/<category_name>/<item_name>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(item_name, category_name):
    """
    Edit Item in the database
    Args : Item name, Category name
    Returns:
        on GET: Page to Edit Item
        on POST: Redirect to Category page after Item has been deleted
        Shows warning and redirects to Category page if not authorized
         to make changes
    """
    item = session.query(Item).filter_by(name=item_name).one()

    if item.user_id != login_session['user_id']:
        flash('WARNING ! Permission denied')
        return redirect(url_for('showItem', category_name=category_name))

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('edititem.html', category_name=category_name,
                               item=item)


@app.route('/catalog/<category_name>/<item_name>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(item_name, category_name):
    """
    Delete Item in the database
    Args : Item name, Category name
    Returns:
        on GET: Page to Delete Item
        on POST: Redirect to main page after Item has been deleted
        Shows warning and redirects to Category page if not authorized
        to make changes
    """

    item = session.query(Item).filter_by(name=item_name).one()

    if item.user_id != login_session['user_id']:
        flash('WARNING ! Permission denied')
        return redirect(url_for('showItem', category_name=category_name))

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('deleteitem.html', item=item,
                               category_name=category_name)


@app.route('/catalog.json')
def getCatalogJSON():
    """Return JSON for all the categories and items"""
    categorys = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categorys])


@app.route('/catalog/<category_name>/<item_name>/JSON')
def getItemJSON(item_name, category_name):
    """
    :param item_name
    :param category_name
    :return: JSON for the item details
    """
    item = session.query(Item).filter_by(name=item_name).one()
    return jsonify(item.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000, threaded=False)
