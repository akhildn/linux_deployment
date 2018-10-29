from flask import (Flask, render_template,
                   redirect, request, jsonify,
                   url_for, flash)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
app.secret_key = 'super_secret_key'


# connects to the database
engine = create_engine('postgresql://catalog:grader@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# retrieves and stores client id from the secret credentials json file
CLIENT_ID = json.loads(
    open('/var/www/catalog/client_secrets.json', 'r').read())['web']['client_id']
# Application's name
APPLICATION_NAME = "Restaurant Catalog"


@app.route("/login")
def login():
    """
    This method is used to render login view to the user
    :return: returns login page, with state token which was generated
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('guest/login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    This method is used to authentication through google.
    If authentication is successful then will retrieve
    user's name, email, picture.
    If it was there first login then a user record is created in user table
    :return: if login successful, redirects you to home page.
             Else, throws you an alert.
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/catalog/client_secrets.json', scope='')
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
    result = json.loads(h.request(url, 'GET')[1].decode("utf-8"))
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
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px;' \
              'border-radius: 150px;' \
              '-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    return output


# User Helper Functions
def createUser(login_session):
    """
    Creates a user record in user table
    :param login_session:
    :return: user id, id of the user record which was just created
    """
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    """
    Method to disconnect. empties login_session.
    :return: On successful disconnect, redirects to homepage,
             else throws an error
    """
    access_token = login_session['access_token']
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect("/")
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    """
    Retrieves all restaurants from the database and passes it on to the view.
    :return: returns restaurants page which lists out all the restaurants
    """
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    return render_template('guest/restaurants.html', restaurants=restaurants)


# Create a new restaurant


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    """
    Method to create a new restaurant.
    Only logged in/registered user can create a restaurant
    :return: if user not logged in
                then returns login page
             else
                returns a page from where you can add a restaurant
             if request method was POST
                then it will create a new record of used created restaurant
                and redirects to show restaurants page(home page)
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'],
            cuisine=request.form['cuisine'],
            address=request.form['address'],
            user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('user/newRestaurant.html')


# Edit a restaurant


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    """
     Method to edit restaurant details like name, cuisine, address
     And only the user who has created the restaurant can edit restaurant
    :param restaurant_id:
    :return: Method GET:
                if not logged in then
                    redirects to login page
                if user is logged in
                    redirects to the page where you can edit restaurant
             Method POST:
                Updates the restaurant details which
                user has given in edit form
    """
    editRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editRestaurant.user_id != login_session['user_id']:
        return "<script>" \
               "function myFunction() {" \
               "alert('You are not authorized to edit this restaurant. " \
               "Please create your own restaurant in order to edit.');" \
               "}" \
               "</script>" \
               "<body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('user/editRestaurant.html',
                               restaurant=editRestaurant)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    """
    Method to delete restaurant, only the user who created the restaurant
    can delete the restaurant.
    :param restaurant_id:
    :return: Method GET:
                if not logged in then
                    redirects to login page
                if user is logged in
                    redirects to the page where you can delete the restaurant
             Method POST:
                deletes the restaurant
    """
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if restaurantToDelete.user_id != login_session['user_id']:
        return "<script>" \
               "function myFunction() {" \
               "alert('You are not authorized to delete this restaurant. " \
               "Please create your own restaurant in order to delete.');" \
               "}</script>" \
               "<body onload='myFunction()''>"
    if request.method == 'POST':
        deleteMenuItems = session.query(MenuItem).filter_by(
            restaurant_id=restaurant_id).delete()
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants',
                                restaurant_id=restaurant_id))
    else:
        return render_template('user/deleteRestaurant.html',
                               restaurant=restaurantToDelete)


# Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    """
    Method which shows all the items which are avilable in the restaurant.
    Retrieves all the items from the selected restaurant.
    :param restaurant_id:
    :return: If user is logged in then
                redirects to user show menu page which includes
                links to edit, delete and add menu items
             If user is not logged in then
                returns a page where user can only view the items
    """
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    creator = getUserInfo(restaurant.user_id)
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return render_template('guest/menu.html',
                               items=items,
                               restaurant=restaurant,
                               creator=creator)
    else:
        return render_template('user/menu.html',
                               items=items,
                               restaurant=restaurant,
                               creator=creator)


# Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',
           methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    """
    Method to create new menu items. Request method can be POST or get.
    Only the user who created the restaurant can add an item.
    :param restaurant_id:
    :return: Method GET:
                if not logged in then
                    redirects to login page
                if user is logged in
                    redirects to the page where you can add item page
             Method POST:
                adds user given item to the restaurant
    """
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>" \
               "function myFunction() {" \
               "alert('You are not authorized to add menu " \
               "items to this restaurant. " \
               "Please create your own restaurant in order to add items.');" \
               "}</script>" \
               "<body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           course=request.form['course'],
                           restaurant_id=restaurant_id,
                           user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('user/newMenuItem.html',
                               restaurant_id=restaurant_id)


# Edit a menu item


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    """
    Method to edit a menu item in the restaurant.
    Only the user who created the restaurant can edit the item.
    :param restaurant_id:
    :param menu_id:
    :return: Method GET:
                if not logged in then
                    redirects to login page
                if user is logged in
                    redirects to the page where you can edit menu item
             Method POST:
                Updates the item details which
                user has given in edit form
    """
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>" \
               "function myFunction() {" \
               "alert('You are not authorized to edit" \
               " menu items to this restaurant. " \
               "Please create your own restaurant " \
               "in order to edit items.');" \
               "}" \
               "</script>" \
               "<body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('user/editMenuItem.html',
                               restaurant_id=restaurant_id,
                               restaurant=restaurant,
                               menu_id=menu_id, item=editedItem)


# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    """
    Method to delete menu item, only the user who created the restaurant
    can delete the menu item.
    :param restaurant_id:
    :param menu_id:
    :return: Method GET:
                if not logged in then
                    redirects to login page
                if user is logged in
                    redirects to the page where you can delete the menu item
             Method POST:
                deletes the menu item
    """
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(
        id=menu_id, restaurant_id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>" \
               "function myFunction() {" \
               "alert('You are not authorized to delete " \
               "menu items to this restaurant" \
               ". Please create your own restaurant " \
               "in order to delete items.');}" \
               "</script>" \
               "<body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu',
                                restaurant_id=restaurant_id))
    else:
        return render_template('user/deleteMenuItem.html',
                               restaurant=restaurant,
                               item=itemToDelete)


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    """
    API End Point for a restaurant's menu
    :param restaurant_id:
    :return: returns json data of restaurants menu
    """
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    """
    API End Point for a restaurant's menu
    :param restaurant_id:
    :param menu_id:
    :return: returns json dat for a specified item in restaurant's menu
    """
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    """
    API End Point for listing out all the restaurant
    :return: returns json data which contains
             information about all the restaurants
    """
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


if __name__ == '__main__':
    app.debug = True
    app.run()
