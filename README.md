# Project : Item Catalog


## Description
A web application that provides CRUD(Create Read Update Delete) for a list of items within a variety of categories and integrate third party user (Google OAuth) registration and authentication. Authenticated users should have the ability to post, edit, and delete their own items and categories.


## JSON API Structure
The following API endpoints are implemented as part of the project - 

/catalog/<category_name>/<item_name>/JSON</br>
Returns the record for <item_name> from Item table in database as a json file

/catalog.json</br>
Returns the entire Category table from database as a json file


## Running the program
#### Installing Dependencies
The major required software packages to be installed are PostgreSQL, Python3, flask and sqlalchemy

    apt-get -qqy install make zip unzip postgresql
    apt-get -qqy install python3 python3-pip
    pip3 install --upgrade pip
    pip3 install flask packaging oauth2client redis passlib flask-httpauth
    pip3 install sqlalchemy flask-sqlalchemy psycopg2 bleach requests

#### Steps to create db
The database will be automatically created as new categories and items are made using the web application. Alternately,
the following commands can be used to create db from own sql dump -

>su postgres -c 'createuser -dRS \<username\>'</br>
>su \<username\> -c 'psql catalog -f \<path to sql dump file\>'

The table names and fields are given in the model.py file for creating the table in SQL dump file

#### Run Command
To run the program , simply type the below code
```
python application.py
```
Access and test application by visiting http://localhost:5000 locally on your browser.
