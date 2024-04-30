from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from hashlib import sha256
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.secret_key = 'super secret key'
db = SQLAlchemy(app)

API_URL = 'http://192.168.86.61:5000/api'

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
            session.pop('user_id', None)
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

        if User.query.filter_by(username=username).first():
            flash('User already exists')
            return redirect(url_for('admin'))

        user = User(username=username, password=hashed_password, permission=selected_permission)
        db.session.add(user)
        db.session.commit()
        flash('User created')

        return redirect(url_for('admin'))
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

@app.route('/admin/delete_user', methods=['GET'])
def delete_user():
    request_user = User.query.filter_by(id=session['user_id']).first()
    if not request_user or request_user.permission != 'admin':
        return 'You do not have permission to delete users'
    user_id = request.args.get('user_id')
    if user_id == session['user_id']:
        return 'You cannot delete yourself'
    if user_id is None:
        return 'User ID not provided'
    
    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return 'User deleted'
    return 'User not found'

@app.route('/admin/fixtures', methods=['GET'])
def fixtures():
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()
        if user and user.permission == 'admin':
            response = requests.get(API_URL + '/games', headers={'X-Api-Key': 'PN9AbvdtzEBcR1bhuqTfFFbTU846xG3n'})
            if response.status_code == 200:
                games = response.json()
                fixtures = []
                print(games)
                for game in games:
                    fixtures.append({
                        'id': game['GameID'],
                        'home_team': game['HomeTeamName'],
                        'away_team': game['AwayTeamName'],
                        'date': game['Date'],
                        'location': game['Location'],
                    })
                print(games)
                return render_template('admin/fixtures.html', fixtures=fixtures)
            else:
                print("Failed to fetch data: Status code", response.status_code)
                return render_template('admin/fixtures.html', fixtures=[])
    return redirect(url_for('home'))

@app.route('/admin/edit_fixture', methods=['GET', 'POST'])
def edit_fixture():
    if request.method == 'POST':
        fixture_id = request.form['fixture_id']
        home_team = request.form['home_team']
        away_team = request.form['away_team']
        home_score = request.form['home_score']
        away_score = request.form['away_score']
        fixture_date = request.form['fixture_date']
        fixture_time = request.form['fixture_time']

        r = requests.put(f'{API_URL}/games/{fixture_id}', headers={'X-Api-Key': 'PN9AbvdtzEBcR1bhuqTfFFbTU846xG3n'}, json={
            'home_team': home_team,
            'away_team': away_team,
            'home_score': home_score,
            'away_score': away_score,
            'fixture_date': fixture_date,
            'fixture_time': fixture_time
        })

        return 'Fixture updated'
    
    return redirect(url_for('admin'))

@app.route('/admin/delete_fixture', methods=['GET'])
def delete_fixture():
    request_user = User.query.filter_by(id=session['user_id']).first()
    if not request_user or request_user.permission != 'admin':
        return 'You do not have permission to delete fixtures'
    fixture_id = request.args.get('id')
    if fixture_id is None:
        return 'Fixture ID not provided'
    
    r = requests.delete(f'{API_URL}/games/{fixture_id}', headers={'X-Api-Key': 'PN9AbvdtzEBcR1bhuqTfFFbTU846xG3n'})
    if r.status_code == 204:
        flash('Fixture deleted')
        return redirect(url_for('fixtures'))
    flash('Failed to delete fixture')
    return redirect(url_for('fixtures'))

@app.route('/admin/add_fixture', methods=['GET', 'POST'])
def add_fixture():
    if request.method == 'POST':
        home_team = request.form['home_team']
        away_team = request.form['away_team']
        fixture_date = request.form['date']
        location = request.form['location']


        #lookup team IDS: API_URL + '/teams/{team_name}'
        #post Json format: 
        '''
  {"GameID": 0,
  "Date": "string",
  "Location": "string",
  "HomeTeamID": 0,
  "AwayTeamID": 0,
  "CurrentPeriod": "string"}
'''
        def get_team_id(team_name):
            response = requests.get(API_URL + f'/teams/{team_name}', headers={'X-Api-Key': 'PN9AbvdtzEBcR1bhuqTfFFbTU846xG3n'})
            if response.status_code == 200:
                return response.json()['TeamID']
            return None
        
        home_team_id = get_team_id(home_team)
        away_team_id = get_team_id(away_team)

        if home_team_id is None or away_team_id is None:
            return 'Failed to get team IDs'
        
        r = requests.post(f'{API_URL}/games', headers={'X-Api-Key': 'PN9AbvdtzEBcR1bhuqTfFFbTU846xG3n'}, json={
            'Date': fixture_date,
            'Location': location,
            'HomeTeamID': home_team_id,
            'AwayTeamID': away_team_id,
            'CurrentPeriod': 'Unknown'})
        flash('Fixture added' if r.status_code == 201 else 'Failed to add fixture')
        return redirect(url_for('fixtures'))
    return redirect(url_for('fixtures'))

@app.route('/gamesheet', methods=['GET'])
def gamesheet():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('home'))
    if user.permission != 'admin' and user.permission != 'gamesheet':
        return redirect(url_for('home'))
    
    return render_template('gamesheet/home.html')

@app.route('/gamesheet/fixtures', methods=['GET'])
def gamesheet_fixtures():
    response = requests.get(API_URL + '/games', headers={'X-Api-Key': 'PN9AbvdtzEBcR1bhuqTfFFbTU846xG3n'})
    if response.status_code == 200:
        games = response.json()
        fixtures = []
        for game in games:
            fixtures.append({
                'id': game['GameID'],
                'home_team': game['HomeTeamName'],
                'away_team': game['AwayTeamName'],
                'date': game['Date'],
                'location': game['Location'],
            })
        return render_template('gamesheet/fixtures.html', fixtures=fixtures)
    flash('Failed to fetch fixtures')
    return redirect(url_for('gamesheet'))

@app.route('/gamesheet/fixtures/details', methods=['GET'])
def gamesheet_fixture_details():
    fixture_id = request.args.get('id')
    if fixture_id is None:
        flash('Fixture ID not provided')
        return redirect(url_for('gamesheet_fixtures'))
    
    response = requests.get(f'{API_URL}/games/{fixture_id}', headers={'X-Api-Key': 'PN9AbvdtzEBcR1bhuqTfFFbTU846xG3n'})
    if response.status_code == 200:
        game = response.json()
        return render_template('gamesheet/fixture_details.html', fixture=game)
    flash('Failed to fetch fixture details')
    return redirect(url_for('gamesheet_fixtures'))

if __name__ == '__main__':
    app.run(debug=True, host='192.168.86.61', port=3000)
