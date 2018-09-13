from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'crud_flask_env'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MySQL
mysql = MySQL(app)

Articles = Articles()

@app.route('/')
def index():
        return render_template('home.html')

@app.route('/about')
def about():
        return render_template('about.html')

@app.route('/articles')
def articles():
        return render_template('articles.html', articles = Articles)

@app.route('/article/<string:id>/')
def article(id):
        return render_template('article.html', id=id)

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
            validators.DataRequired(),
            validators.EqualTo('confirm', message='Passwords do not match.')
        ])
    confirm = PasswordField('Confirm Password')

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
                msg = 'Correct mane'
                return render_template('login.html', msg=msg)
            else:
                error = 'Invalid Credentials'
                return render_template('login.html', error=error)
        else:
            error = "Username not found."
            return render_template('login.html', error=error)

    return render_template('login.html')

# Should be last line of file
if __name__ == '__main__':
    app.secret_key='secret_key'
    app.run(debug=True)
