import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Get user's stocks and shares
    stocks = db.execute("""
        SELECT symbol, SUM(shares) as total_shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, session["user_id"])

    # Get user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?",
                      session["user_id"])[0]["cash"]

    # Initialize grand total with cash
    grand_total = cash

    # Get current price for each stock and calculate total
    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["shares"] = stock["total_shares"]
        stock["total"] = stock["price"] * stock["shares"]
        grand_total += stock["total"]

    return render_template("index.html",
                           stocks=stocks,
                           cash=cash,
                           grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate symbol
        if not symbol:
            return apology("must provide symbol", 400)

        # Validate shares
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("shares must be positive", 400)
        except ValueError:
            return apology("shares must be a positive integer", 400)

        # Look up stock info
        quote = lookup(symbol)
        if quote is None:
            return apology("invalid symbol", 400)

        # Calculate total cost
        cost = quote["price"] * shares

        # Check user's cash balance
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]

        if cash < cost:
            return apology("can't afford", 400)

        # Update database
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            session["user_id"],
            quote["symbol"],
            shares,
            quote["price"]
        )

        # Update user's cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            cash - cost,
            session["user_id"]
        )

        # Redirect to home page
        return redirect("/")

    # GET request - display form
    symbol = request.args.get("symbol", "")
    return render_template("buy.html", symbol=symbol)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get all transactions for the user
    transactions = db.execute("""
        SELECT *
        FROM transactions
        WHERE user_id = ?
        ORDER BY timestamp DESC
    """, session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)

        stock = lookup(symbol)
        if not stock:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", stock=stock)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not password:
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        if not confirmation:
            return apology("must provide password confirmation", 400)

        # Ensure password and confirmation match
        if password != confirmation:
            return apology("passwords must match", 400)

        # Ensure password is at least 8 characters
        if len(password) < 8:
            return apology("password must be at least 8 characters", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Check if username already exists
        if len(rows) >= 1:
            return apology("username already exists", 400)

        # Insert new user into database
        db.execute(
            "INSERT INTO users (username, hash, cash) VALUES (?, ?, ?)",
            username,
            generate_password_hash(password),
            10000.00
        )

        # Redirect user to login page
        return redirect("/login")

    # GET request - show registration form
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate symbol
        if not symbol:
            return apology("must select a symbol", 400)

        # Validate shares
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("shares must be positive", 400)
        except ValueError:
            return apology("shares must be a positive integer", 400)

        # Check ownership and sufficient shares
        rows = db.execute("""
            SELECT SUM(shares) as total_shares
            FROM transactions
            WHERE user_id = ? AND symbol = ?
            GROUP BY symbol
        """, session["user_id"], symbol)

        if not rows or rows[0]["total_shares"] < shares:
            return apology("not enough shares", 400)

        # Get current stock price
        quote = lookup(symbol)
        if quote is None:
            return apology("symbol not found", 400)

        # Calculate proceeds
        proceeds = quote["price"] * shares

        # Record sale transaction (negative shares for sales)
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            session["user_id"],
            symbol,
            -shares,
            quote["price"]
        )

        # Update user's cash
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            proceeds,
            session["user_id"]
        )

        return redirect("/")

    # GET request - display form with user's stocks
    stocks = db.execute("""
        SELECT symbol, SUM(shares) as total_shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, session["user_id"])

    # Pre-select symbol if provided
    selected_symbol = request.args.get("symbol")
    return render_template("sell.html", stocks=stocks, selected_symbol=selected_symbol)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=80)