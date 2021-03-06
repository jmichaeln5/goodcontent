from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
# from flask_ckeditor import CKEditor
from wtforms import TextAreaField
# from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
# ckeditor= CKEditor(app)

# Config MySQL
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = ''
# app.config['MYSQL_DB'] = 'crud_flask_env'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
#
# # init MySQL
# mysql = MySQL(app)




### CLEARDB_DATABASE_URL: mysql://b156f23ccdb67c:cdd233ab@us-cdbr-iron-east-01.cleardb.net/heroku_db4c834d154399d?reconnect=true

# Config MySQL
app.config['MYSQL_HOST'] = 'us-cdbr-iron-east-01.cleardb.net/'
app.config['MYSQL_USER'] = 'b156f23ccdb67c'
app.config['MYSQL_PASSWORD'] = 'cdd233ab '
app.config['MYSQL_DB'] = 'heroku_db4c834d154399d'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MySQL
mysql = MySQL(app)






# Grabs Data from Artice File
# Articles = Articles()

#####################################
@app.route('/')
def index():
        return render_template('home.html')

#####################################
# About
@app.route('/about')
def about():
        return render_template('about.html')

#####################################
#  Articles
@app.route('/articles')
def articles():
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get Articles
    result = cur.execute("SELECT * FROM articles")

    articles = cur.fetchall()

    if result > 0:
            return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html')
    # Close connection
    cur.close()

#####################################
# Single Article
@app.route('/article/<string:id>/')
def article(id):
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get Article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)

#####################################
# Start of Register
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
            validators.DataRequired(),
            validators.EqualTo('confirm', message='Passwords do not match.')
        ])
    confirm = PasswordField('Confirm Password')

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create MySQL Cursor - Inputs form Data to Database
        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to  DB
        mysql.connection.commit()

        # Close DB Connection
        cur.close()

        flash('Thank You for Signing Up. Please Navigate to Login Page to Sign In.')

        return redirect(url_for('login'))

        # return render_template('register.html')
    return render_template('register.html', form=form)

#####################################
@app.route('/login', methods=['GET', 'POST'] )
def login():
    if request.method == 'POST':

        #Get Form Fields
        username = request.form['username']
        password_canidate = request.form['password']

        #Create Cursor for MySQL
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            #Get stored hash
            data = cur.fetchone()
            password = data['password']

            #Compare Passwords
            if sha256_crypt.verify(password_canidate, password):
                #Passed
                session['logged_in'] = True
                session['username'] = username

                flash('Logged in mane', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Credentials'
                return render_template('login.html', error=error)
            #  Close Connection
            cur.close

        else:
            error = "Username not found."
            return render_template('login.html', error=error)

    return render_template('login.html')

# Checks if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

#####################################
# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out.', 'success')
    return redirect(url_for('login'))

#####################################
# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get Articles
    result = cur.execute("SELECT * FROM articles")

    articles = cur.fetchall()

    if result > 0:
            return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html')
    # Close connection
    cur.close()

# Article Form Class
class ArticleForm(Form):
    title = StringField('Name', [validators.Length(min=1, max=200)])
    body = StringField('Body', [validators.Length(min=10)])

#####################################
# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s ,%s)",(title, body, session['username']))

        # Commit
        mysql.connection.commit()

        # Close connect
        cur.close

        flash('Your article hads been created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)

#####################################
# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    # Create Cursor
    cur = mysql.connection.cursor()

    #  Get article by ID
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    # Get form
    form = ArticleForm(request.form)

    # Populate artice form fields
    form.title.data = article['title']
    form.body.data = article['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("UPDATE articles SET title=%s, body=%s WHERE id =%s", (title, body, id ))

        # Commit
        mysql.connection.commit()

        # Close connect
        cur.close

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

#####################################
# Delete Article
# @app.route('/delete_article/<string:id>', methods=['POST'])
@app.route('/delete_article/<string:id>')
@is_logged_in
def delete_article(id):
    # Create Cursor
    cur = mysql.connection.cursor()

    #  Execute
    cur.execute("DELETE FROM articles WHERE id=%s", [id])

    # Commit
    mysql.connection.commit()

    # Close connect
    cur.close

    flash('Article Deleted', 'success')

    return redirect(url_for('dashboard'))


#####################################
#####################################
#####################################
# Should be last line of file
if __name__ == '__main__':
    app.secret_key='secret_key'
    app.run(debug=True)
