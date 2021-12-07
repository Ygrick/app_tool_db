import hashlib
from flask import Flask, render_template, request, redirect, session, url_for
from flaskext.mysql import MySQL
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from handler import *

app = Flask(__name__)
app.secret_key = 'Mage is the best!'

# MySQL
mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = "root"
app.config['MYSQL_DATABASE_PASSWORD'] = "zbujhm2001"
app.config['MYSQL_DATABASE_DB'] = "economy_bot"
app.config['MYSQL_DATABASE_HOST'] = "localhost"
mysql.init_app(app)


def login_required(f):
	@wraps(f)
	def wrapped(*args, **kwargs):
		if 'authorised' not in session:
			return render_template('login.html')
		return f(*args, **kwargs)
	return wrapped


@app.context_processor
def inject_tables_and_counts():
	data = count_all(mysql)
	return dict(tables_and_counts=data)


@app.route('/')
@app.route('/index')
@login_required
def index():
	return render_template('index.html')


@app.route("/app")
@login_required
def _app():
	data = fetch_all(mysql, "app")
	return render_template('app.html', data=data, table_count=len(data))


@app.route('/edit_app/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_app(modifier_id, act):
	if act == "add":
		return render_template('edit_app.html', data="", act="add")
	else:
		data = fetch_one(mysql, "app", "id", modifier_id)
	
		if data:
			return render_template('edit_app.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/count_each_webserver")
@login_required
def count_each_webserver():
	data = fetch_all(mysql, "count_each_webserver")
	return render_template('count_each_webserver.html', data=data, table_count=len(data))


@app.route('/edit_count_each_webserver/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_count_each_webserver(modifier_id, act):
	if act == "add":
		return render_template('edit_count_each_webserver.html', data="", act="add")
	else:
		data = fetch_one(mysql, "count_each_webserver", "id_server", modifier_id)
	
		if data:
			return render_template('edit_count_each_webserver.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/crypto")
@login_required
def crypto():
	data = fetch_all(mysql, "crypto")
	return render_template('crypto.html', data=data, table_count=len(data))


@app.route('/edit_crypto/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_crypto(modifier_id, act):
	if act == "add":
		return render_template('edit_crypto.html', data="", act="add")
	else:
		data = fetch_one(mysql, "crypto", "company", modifier_id)
	
		if data:
			return render_template('edit_crypto.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/currency")
@login_required
def currency():
	data = fetch_all(mysql, "currency")
	return render_template('currency.html', data=data, table_count=len(data))


@app.route('/edit_currency/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_currency(modifier_id, act):
	if act == "add":
		return render_template('edit_currency.html', data="", act="add")
	else:
		data = fetch_one(mysql, "currency", "code_currency", modifier_id)
	
		if data:
			return render_template('edit_currency.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/diagram")
@login_required
def diagram():
	data = fetch_all(mysql, "diagram")
	return render_template('diagram.html', data=data, table_count=len(data))


@app.route('/edit_diagram/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_diagram(modifier_id, act):
	if act == "add":
		return render_template('edit_diagram.html', data="", act="add")
	else:
		data = fetch_one(mysql, "diagram", "code_currency", modifier_id)
	
		if data:
			return render_template('edit_diagram.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/fiat")
@login_required
def fiat():
	data = fetch_all(mysql, "fiat")
	return render_template('fiat.html', data=data, table_count=len(data))


@app.route('/edit_fiat/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_fiat(modifier_id, act):
	if act == "add":
		return render_template('edit_fiat.html', data="", act="add")
	else:
		data = fetch_one(mysql, "fiat", "country", modifier_id)
	
		if data:
			return render_template('edit_fiat.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/sum_each_cur_of_user")
@login_required
def sum_each_cur_of_user():
	data = fetch_all(mysql, "sum_each_cur_of_user")
	return render_template('sum_each_cur_of_user.html', data=data, table_count=len(data))


@app.route('/edit_sum_each_cur_of_user/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_sum_each_cur_of_user(modifier_id, act):
	if act == "add":
		return render_template('edit_sum_each_cur_of_user.html', data="", act="add")
	else:
		data = fetch_one(mysql, "sum_each_cur_of_user", "id", modifier_id)
	
		if data:
			return render_template('edit_sum_each_cur_of_user.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/user")
@login_required
def user():
	data = fetch_all(mysql, "user")
	return render_template('user.html', data=data, table_count=len(data))


@app.route('/edit_user/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_user(modifier_id, act):
	if act == "add":
		return render_template('edit_user.html', data="", act="add")
	else:
		data = fetch_one(mysql, "user", "id_of_user", modifier_id)
	
		if data:
			return render_template('edit_user.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/users")
@login_required
def users():
	data = fetch_all(mysql, "users")
	return render_template('users.html', data=data, table_count=len(data))


@app.route('/edit_users/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_users(modifier_id, act):
	if act == "add":
		return render_template('edit_users.html', data="", act="add")
	else:
		data = fetch_one(mysql, "users", "id", modifier_id)
	
		if data:
			return render_template('edit_users.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/wallet")
@login_required
def wallet():
	data = fetch_all(mysql, "wallet")
	return render_template('wallet.html', data=data, table_count=len(data))


@app.route('/edit_wallet/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_wallet(modifier_id, act):
	if act == "add":
		return render_template('edit_wallet.html', data="", act="add")
	else:
		data = fetch_one(mysql, "wallet", "id", modifier_id)
	
		if data:
			return render_template('edit_wallet.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/webserver")
@login_required
def webserver():
	data = fetch_all(mysql, "webserver")
	return render_template('webserver.html', data=data, table_count=len(data))


@app.route('/edit_webserver/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_webserver(modifier_id, act):
	if act == "add":
		return render_template('edit_webserver.html', data="", act="add")
	else:
		data = fetch_one(mysql, "webserver", "id_server", modifier_id)
	
		if data:
			return render_template('edit_webserver.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route('/save', methods=['GET', 'POST'])
@login_required
def save():
	cat = ''
	if request.method == 'POST':
		post_data = request.form.to_dict()
		if 'password' in post_data:
			post_data['password'] = generate_password_hash(post_data['password']) 
		if post_data['act'] == 'add':
			cat = post_data['cat']
			insert_one(mysql, cat, post_data)
		elif post_data['act'] == 'edit':
			cat = post_data['cat']
			update_one(mysql, cat, post_data, post_data['modifier'], post_data['id'])
	else:
		if request.args['act'] == 'delete':
			cat = request.args['cat']
			delete_one(mysql, cat, request.args['modifier'], request.args['id'])
	return redirect("./" + cat)


@app.route('/login')
def login():
	if 'authorised' in session:
		return redirect(url_for('index'))
	else:
		error = request.args['error'] if 'error' in request.args else ''
		return render_template('login.html', error=error)


@app.route('/login_handler', methods=['POST'])
def login_handler():
	try:
		email = request.form['email']
		password = request.form['password']
		data = fetch_one(mysql, "users", "email", email)
		
		if data and len(data) > 0:
			if check_password_hash(data[3], password) or hashlib.md5(password.encode('utf-8')).hexdigest() == data[3]:
				session['authorised'] = 'authorised',
				session['id'] = data[0]
				session['name'] = data[1]
				session['email'] = data[2]
				session['role'] = data[4]
				return redirect(url_for('index'))
			else:
				return redirect(url_for('login', error='Wrong Email address or Password.'))
		else:
			return redirect(url_for('login', error='No user'))
	
	except Exception as e:
		return render_template('login.html', error=str(e))


@app.route('/logout')
@login_required
def logout():
	session.clear()
	return redirect(url_for('login'))


if __name__ == "__main__":
	app.run(debug=True)
