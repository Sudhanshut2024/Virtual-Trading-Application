from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, make_response, g
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, Length
import bcrypt
from flask_mysqldb import MySQL
import requests
import os
import logging
import MySQLdb
from werkzeug.security import check_password_hash  # Import the check_password_hash function



# import logging
# from flask import Flask, g, render_template, request, redirect, url_for, flash, session
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired
# import mysql.connector  # Assuming MySQL is used

app = Flask(__name__)

# Load secret key and MySQL configuration from environment variables
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'admin123')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'mydatabase')
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key_here')

mysql = MySQL(app)

# NSE class to fetch stock data
class NSE:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
        }

        
# Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
        self.session = requests.Session()
        self.session.get('https://www.nseindia.com', headers=self.headers)

    def equity_info(self, symbol):
        symbol = symbol.replace(' ', '%20').replace('&', '%26')
        url = f'https://www.nseindia.com/api/quote-equity?symbol={symbol}'

        try:
            response = self.session.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            return data.get('priceInfo', {}).get('lastPrice', 'Value not found')
        except requests.RequestException as e:
            print(f"Request error: {e}")
            return 'Failed to fetch stock price. Please try again.'
        except Exception as e:
            print(f"Error processing response: {e}")
            return 'Failed to fetch stock price. Please try again.'        

    def get_equity_index_data(self, index_name):
        """Fetch data for a specific equity index (e.g., NIFTY 50, NIFTY BANK)."""
        index_name = index_name.upper().replace(' ', '%20').replace('&', '%26')
        try:
            response = self.session.get(f"https://www.nseindia.com/api/equity-stockIndices?index={index_name}", headers=self.headers)
            response.raise_for_status()
            stocks_data = response.json().get("data", None)

            if stocks_data:
                # Extract stock symbols and last prices
                stock_prices = {stock['symbol']: stock['lastPrice'] for stock in stocks_data}
                return stock_prices
            else:
                return f"No 'data' found for index: {index_name}"
        except requests.RequestException as e:
            print(f"Request error: {e}")
            return "Failed to fetch market data."
        except ValueError:
            return "Failed to parse response."


        
        


# WTForms for registration and login

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])  # Add this line
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


def fetch_all_stocks_for_indices():
    nse = NSE()
    indices = ['NIFTY 50', 'NIFTY BANK', 'NIFTY FINANCIAL SERVICES']
    all_stocks = {}

    for index in indices:
        data = nse.get_equity_index_data(index)
        # Check if data is a dictionary (which it should be if it's successful)
        if isinstance(data, dict):
            all_stocks[index] = data
        else:
            all_stocks[index] = {}  # No stocks found for this index or an error occurred

    print(all_stocks)  # Debugging: Print the fetched stocks data
    return all_stocks



@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            index_data = fetch_index_data()  # Fetch existing index data
            all_stocks_data = fetch_all_stocks_for_indices()  # Fetch all stocks for indices
            response = make_response(render_template('dashboard.html', user=user, index_data=index_data, all_stocks_data=all_stocks_data))
            response.headers['Cache-Control'] = 'no-store'
            return response

    flash("You need to log in first.")
    return redirect(url_for('login'))



def fetch_index_data():
    nse = NSE()
    indices = ['NIFTY 50', 'NIFTY BANK', 'NIFTY MIDCAP SELECT', 'NIFTY FINANCIAL SERVICES' , 'NIFTY NEXT 50' , 'NIFTY 100', 'NIFTY 200' , 'NIFTY 500', 'NIFTY IT', 'NIFTY FMCG', 'NIFTY METAL', 'NIFTY PHARMA', 'NIFTY REALTY', 'NIFTY PRIVATE BANK', 'NIFTY OIL & GAS', 'NIFTY PSU BANK']
    index_data = {}

    for index in indices:
        data = nse.get_equity_index_data(index)
        # Store only the last price if the data is not a string
        if isinstance(data, dict):
            last_price = data.get(index, 'Price not found')
            index_data[index] = last_price
        else:
            index_data[index] = data  # Store the error message

    return index_data
   
from flask import jsonify

@app.route('/get-index-data')
def get_index_data():
    index_data = fetch_index_data()  # Call your function that fetches the index data
    return jsonify(index_data)


@app.route('/')
def index():
    index_data = fetch_index_data()  # Fetch index data for non-logged-in users
    return render_template('index.html', index_data=index_data)
   





@app.route('/api/my-portfolio')
def get_portfolio():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    
    # Fetch stock symbol, quantity, and purchase price from the portfolio table
    cursor.execute("SELECT stock_symbol, quantity, purchase_price FROM portfolio WHERE user_id=%s", (user_id,))
    portfolio_items = cursor.fetchall()
    cursor.close()

    # Format the portfolio data to send as JSON
    portfolio_data = []
    for stock_symbol, quantity, purchase_price in portfolio_items:
        # Fetch the current price from NSE API (assuming nse.equity_info function works)
        current_price = nse.equity_info(stock_symbol)
        
        portfolio_data.append({
            'ticker': stock_symbol,
            'quantity': quantity,
            'price': current_price,  # Current market price
            'purchase_price': purchase_price,  # Include purchase price
            'name': stock_symbol,  # Assuming stock symbol is used as company name
        })

    # Return portfolio data as JSON
    return jsonify({'portfolio': portfolio_data})


@app.route('/search', methods=['POST'])
def search():
    stock_symbol = request.form.get('stock_symbol')
    if not stock_symbol:
        return jsonify({'error': 'No stock symbol provided.'}), 400

    price = nse.equity_info(stock_symbol)
    if 'Value not found' in price:
        return jsonify({'error': price}), 404

    return jsonify({'stock_symbol': stock_symbol, 'price': price})

@app.route('/stock-price')
def stock_price():
    symbol = request.args.get('symbol')
    if not symbol:
        return jsonify({'error': 'Stock symbol is missing'}), 400
    
    price = nse.equity_info(symbol)
    if price == 'Value not found':
        return jsonify({'error': 'Stock not found'}), 404

    return jsonify({'price': price})

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        username = form.username.data  # Assuming you have added username to the form

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor = mysql.connection.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, password, username, virtual_funds) VALUES (%s, %s, %s, %s, %s)",
                (name, email, hashed_password.decode('utf-8'), username, 100000.00)  # Set virtual_funds to 100000.00
            )
            mysql.connection.commit()
            cursor.close()
            flash("Registration successful! You have been credited with 100,000 virtual funds. Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            flash("An error occurred while registering. Please try again.", "danger")

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()

        # Check if user exists and password matches
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            flash("Login successful!", "success")  # Flash login success message as success
            return redirect(url_for('dashboard'))  # Redirect to dashboard after login
        else:
            flash("Login failed. Please check your email and password.", "danger")  # Flash error message as danger

    # Render the login form with validation errors if any
    return render_template('login.html', form=form)







@app.route('/profile')
def profile():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        return render_template('profile.html', user=user)

    flash("You need to log in first.")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

# @app.route('/portfolio')
# def portfolio():
#     if 'user_id' not in session:
#         flash("You need to log in first.")
#         return redirect(url_for('login'))

#     user_id = session['user_id']
#     cursor = mysql.connection.cursor()
#     cursor.execute("SELECT stock_symbol, quantity, purchase_price FROM portfolio WHERE user_id=%s", (user_id,))
#     portfolio_items = cursor.fetchall()
#     cursor.close()

#     return render_template('portfolio.html', portfolio_items=portfolio_items)
@app.route('/portfolio')
def portfolio():
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    # Fetch portfolio items, excluding those with quantity zero
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT stock_symbol, quantity, purchase_price 
        FROM portfolio 
        WHERE user_id = %s AND quantity > 0
    """, (user_id,))
    portfolio_items = cursor.fetchall()
    
    # Fetch user information
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    
    cursor.close()

    # Pass both portfolio_items and user information to the template
    return render_template('portfolio.html', portfolio_items=portfolio_items, user=user)





@app.route('/my-watchlist')
def watchlist():
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()

    # Fetch watchlist items along with their quantities from the portfolio
    cursor.execute("""
        SELECT w.item_id, p.quantity 
        FROM watchlist w
        LEFT JOIN portfolio p ON w.item_id = p.stock_symbol AND p.user_id = %s
        WHERE w.user_id = %s
    """, (user_id, user_id))
    
    watchlist_items = cursor.fetchall()

    watchlist_data = []
    for item in watchlist_items:
        stock_symbol = item[0]
        quantity = item[1] if item[1] is not None else 0  # Default to 0 if no quantity exists
        stock_price = nse.equity_info(stock_symbol)  # Fetch real-time stock price
        watchlist_data.append({
            'symbol': stock_symbol,
            'price': stock_price,
            'quantity': quantity  # Include the quantity in the data
        })

    cursor.close()
    
    # Prevent the browser from caching the watchlist page
    response = make_response(render_template('watchlist.html', watchlist_data=watchlist_data))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'  # Force expiration in the past
    
    return response




@app.route('/add-to-watchlist', methods=['POST'])
def add_to_watchlist():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You need to log in first.'}), 403

    data = request.get_json()
    stock_name = data.get('stock_name')

    if not stock_name:
        return jsonify({'success': False, 'message': 'No stock name provided.'}), 400

    user_id = session['user_id']

    try:
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO watchlist (user_id, item_id) VALUES (%s, %s)", (user_id, stock_name))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'success': True, 'message': 'Stock added to watchlist!'})
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error adding to watchlist: {e}")
        return jsonify({'success': False, 'message': "An error occurred. Please try again."}), 500


@app.route('/remove-from-watchlist', methods=['POST'])
def remove_from_watchlist():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You need to log in first.'}), 403

    data = request.get_json()
    stock_name = data.get('stock_name')

    if not stock_name:
        return jsonify({'success': False, 'message': 'No stock name provided.'}), 400

    user_id = session['user_id']

    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM watchlist WHERE user_id=%s AND item_id=%s", (user_id, stock_name))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'success': True, 'message': 'Stock removed from watchlist!'})
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error removing from watchlist: {e}")
        return jsonify({'success': False, 'message': "An error occurred. Please try again."}), 500


@app.route('/buy-stock', methods=['POST'])
def buy_stock():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You need to log in first.'}), 403

    data = request.get_json()
    stock_name = data.get('stock_name')
    quantity = data.get('quantity')

    if not stock_name or quantity is None:
        return jsonify({'success': False, 'message': 'Stock name or quantity not provided.'}), 400

    try:
        quantity = int(quantity)
        if quantity <= 0:
            return jsonify({'success': False, 'message': 'Quantity must be greater than zero.'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Quantity must be a valid number.'}), 400

    user_id = session['user_id']

    stock_price = nse.equity_info(stock_name)
    if isinstance(stock_price, str) and 'Value not found' in stock_price:
        return jsonify({'success': False, 'message': stock_price}), 500

    total_cost = stock_price * quantity

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT virtual_funds FROM users WHERE id = %s", (user_id,))
    user_fund = cursor.fetchone()

    if not user_fund:
        return jsonify({'success': False, 'message': 'User not found.'}), 400

    user_fund = user_fund[0]

    if user_fund < total_cost:
        return jsonify({'success': False, 'message': 'Insufficient virtual funds to buy stock.'}), 400

    try:
        # Update the user's virtual funds
        cursor.execute("UPDATE users SET virtual_funds = virtual_funds - %s WHERE id = %s", (total_cost, user_id))

        # Insert or update stock in portfolio
        cursor.execute("""
            INSERT INTO portfolio (user_id, stock_symbol, quantity, purchase_price) 
            VALUES (%s, %s, %s, %s) 
            ON DUPLICATE KEY UPDATE 
                quantity = quantity + VALUES(quantity), 
                purchase_price = VALUES(purchase_price)""",
            (user_id, stock_name, quantity, stock_price))

        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error buying stock: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while processing your request.'}), 500
    finally:
        cursor.close()

    return jsonify({'success': True, 'message': 'Stock purchased successfully!'})



@app.route('/sell-stock', methods=['POST'])
def sell_stock():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'You need to log in first.'}), 403

    data = request.get_json()
    stock_name = data.get('stock_name')
    quantity = data.get('quantity')

    if not stock_name or quantity is None:
        return jsonify({'success': False, 'message': 'Stock name or quantity not provided.'}), 400

    try:
        quantity = int(quantity)
        if quantity <= 0:
            return jsonify({'success': False, 'message': 'Quantity must be greater than zero.'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Quantity must be a valid number.'}), 400

    user_id = session['user_id']
    
    # Fetch the current stock price using equity_info method
    stock_price = nse.equity_info(stock_name)
    if isinstance(stock_price, str) and 'Value not found' in stock_price:
        return jsonify({'success': False, 'message': stock_price}), 500

    total_value = stock_price * quantity

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT quantity FROM portfolio WHERE user_id = %s AND stock_symbol = %s", (user_id, stock_name))
    portfolio_data = cursor.fetchone()

    if not portfolio_data:
        return jsonify({'success': False, 'message': 'You do not own this stock.'}), 400

    current_quantity = portfolio_data[0]
    print(f"Trying to sell {quantity} of {stock_name}. Current quantity in portfolio: {current_quantity}")

    if current_quantity < quantity:
        return jsonify({'success': False, 'message': 'You do not have enough quantity to sell.'}), 400

    new_quantity = current_quantity - quantity

    try:
        if new_quantity > 0:
            # Update quantity in portfolio
            cursor.execute("UPDATE portfolio SET quantity = %s WHERE user_id = %s AND stock_symbol = %s",
                           (new_quantity, user_id, stock_name))
        else:
            # Delete stock entry if quantity is zero
            cursor.execute("DELETE FROM portfolio WHERE user_id = %s AND stock_symbol = %s", (user_id, stock_name))

        # Update the user's virtual funds
        cursor.execute("UPDATE users SET virtual_funds = virtual_funds + %s WHERE id = %s", (total_value, user_id))
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error selling stock: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while processing your request.'}), 500
    finally:
        cursor.close()

    return jsonify({'success': True, 'message': 'Stock sold successfully!'})


@app.route('/terms')
def terms():
    return render_template('terms.html')
    
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')
@app.route('/about')
def about():
    return render_template('about.html')

    
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to submit feedback.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        feedback_text = request.form['feedback']

        cursor = mysql.connection.cursor()
        try:
            query = "INSERT INTO feedback (user_id, feedback_text) VALUES (%s, %s)"
            cursor.execute(query, (session['user_id'], feedback_text))
            mysql.connection.commit()
            flash("Thank you for your feedback!")  # Only flash feedback-related messages
        except Exception as err:
            flash(f"Error submitting feedback: {err}")
        finally:
            cursor.close()

        # Redirect to avoid form resubmission and flash message duplication
        return redirect(url_for('feedback'))

    # Render the feedback form
    return render_template('feedback.html')




# now i am going to create the admin panel of my website 
def get_db():
    if 'db' not in g:
        g.db = mysql.connection
    return g.db

# Admin login form using Flask-WTF
class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Route to add an admin (using plain text passwords)
@app.route('/admin/add', methods=['GET', 'POST'])
def add_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Storing plain text password for now

        # Insert into the database
        cursor = mysql.connection.cursor()
        try:
            query = "INSERT INTO admins (username, password) VALUES (%s, %s)"
            cursor.execute(query, (username, password))  # Store password directly
            mysql.connection.commit()
            flash("Admin added successfully!", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error adding admin: {e}", "danger")
        finally:
            cursor.close()

        return redirect(url_for('admin_dashboard'))  # Redirect after successful addition

    return render_template('add_admin.html')  # Render the form if GET request

# Admin login with plain text password comparison
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = %s", (username,))
        admin = cursor.fetchone()
        cursor.close()

        if admin and password == admin[2]:
            session['admin_id'] = admin[0]
            logging.debug("Login successful for admin: %s", username)
            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            logging.debug("Invalid login attempt for admin: %s", username)
            flash("Invalid credentials", "danger")

    return render_template('admin_login.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    session.clear() 
    logging.debug("Admin logged out")
    flash("You have been logged out", "success")
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor()

    # Fetch total user count
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    # Fetch total stock count
    cursor.execute("SELECT COUNT(*) FROM portfolio")
    stock_count = cursor.fetchone()[0]

    # Fetch all users for displaying in the dashboard
    cursor.execute("SELECT id, username, email FROM users")
    users = cursor.fetchall()
    cursor.close()

    # Render template with no cache headers
    response = make_response(render_template('admin_dashboard.html', user_count=user_count, stock_count=stock_count, users=users))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    return response

# Route to manage users
@app.route('/admin/manage_users')
def manage_users():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, username, email FROM users")  # Removed is_admin
    users = cursor.fetchall()
    cursor.close()

    return render_template('manage_users.html', users=users)

# Route to delete a user

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM portfolio WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()
        flash("User deleted successfully!", "success")  # Flash only once
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting user: {str(e)}", "danger")
    finally:
        cursor.close()

    return redirect(url_for('manage_users'))


# Route to edit a user
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor()
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']  # Handle password securely
        virtual_funds = request.form['virtual_funds']

        # Hash the password if it's provided
        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute("UPDATE users SET username = %s, email = %s, password = %s, virtual_funds = %s WHERE id = %s",
                           (username, email, hashed_password, virtual_funds, user_id))
        else:
            cursor.execute("UPDATE users SET username = %s, email = %s, virtual_funds = %s WHERE id = %s",
                           (username, email, virtual_funds, user_id))

        mysql.connection.commit()
        flash("User updated successfully!", "success")
        return redirect(url_for('manage_users'))

    # Retrieve user details for editing
    cursor.execute("SELECT name, email, virtual_funds FROM users WHERE id = %s", (user_id,))  # Removed is_admin
    user = cursor.fetchone()
    cursor.close()

    return render_template('edit_user.html', user=user)

if __name__ == '__main__':
    nse = NSE()  # Initialize NSE class instance
    app.run(debug=True)
