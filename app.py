from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from hashlib import sha256

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.secret_key = 'super secret key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    permission = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = sha256(password.encode()).hexdigest()
        user = User.query.filter_by(username=username).first()
        if user and user.password == hashed_password:
            session['user_id'] = user.id
            return redirect(url_for('admin' if user.permission == 'admin' else 'index'))
        else:
            return 'Wrong username or password'

    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()
        if not user:
            return "Error"
        if user.permission == 'admin':
            return redirect(url_for('admin'))
        else:
            # The user is logged in but not an admin
            return render_template('some_user_homepage.html')

    return render_template('index.html')

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/admin', methods=['GET'])
def admin():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    user = User.query.filter_by(id=session['user_id']).first()
    if user and user.permission == 'admin':
        return render_template('admin/admin.html')
    return redirect(url_for('home'))

@app.route('/admin/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = sha256(password.encode()).hexdigest()
        selected_permission = request.form['permission']

        user = User(username=username, password=hashed_password, permission=selected_permission)
        db.session.add(user)
        db.session.commit()

        return 'User created'
    return render_template('admin/register.html')

@app.route('/admin/users', methods=['GET'])
def users():
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()
        if user and user.permission == 'admin':
            users = User.query.all()
            return render_template('admin/users.html', users=users)
    return redirect(url_for('home'))

@app.route('/admin/edit_user', methods=['GET', 'POST'])
def edit_user():
    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.filter_by(id=user_id).first()
        if user:
            user.username = request.form['username']
            password = request.form['password']
            if password:
                user.password = sha256(password.encode()).hexdigest()
            user.permission = request.form['permission']
            db.session.commit()
            return 'User updated'
        return 'User not found'
    return redirect(url_for('admin'))

@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    user_id = request.form['user_id']
    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return 'User deleted'
    return 'User not found'

if __name__ == '__main__':
    app.run(debug=True, host='192.168.86.61', port=3000)
