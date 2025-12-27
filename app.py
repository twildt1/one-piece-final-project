import os
import requests

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, search_character

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#here I am going to configure my cs50 library to connect to my db
db = SQL("sqlite:///one_piece.db")



@app.route("/")
def index():
    #if my user does not provide a user id
    if not session.get("user_id"):
        #redirect them to the homepage
        return redirect("/login")
    return render_template("index.html")

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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # if the user uses get they are not posting anything and only going to our page
    if request.method == "GET":
        return render_template("register.html")

    # when our user has reached the route via POST
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    # now we have to  validate if our user provides a username, password, and if the password and confirmation match
    if not username:
        return apology("you must provide a username", 400)
    if not password:
        return apology("you must provide a password", 400)
    if not confirmation:
        return apology("you must confirm your password", 400)
    # if the users password and confirmation do not match
    if password != confirmation:
        return apology("passwords do not match", 400)

    # now we check if our username already exist within our db
    rows = db.execute("SELECT * FROM users WHERE username = ?", username)
    # if the query in our db returns something, then we have to return an apology to our user
    # this means that the username already exist within our db
    if len(rows) != 0:
        return apology("username already exist", 400)

    # need to hash the password
    hash = generate_password_hash(password)

    # next we inset our new user
    user_id = db.execute(
        "INSERT INTO users (username, hash) VALUES (?, ?)",
        username,
        hash
    )

    # for simplicity sake the user should automatically be logged in after registering
    session["user_id"] = user_id

    # finally, we will redirect the user back to the login page
    return redirect("/")

#Next i am going to create my search function
@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        #if the method is post then we will need to grab the dayta from my HTML's name attributes we created in the search.html
        #query refers to the Search for a pirate, captain, or crew! I created in my HTML
        query = request.form.get("query")
        #we defined 3 search types within search types:
            #character
            #user
            #crew
        search_type = request.form.get("search_type")

        #need to perform validation tom be sure they provide something for the search
        if not query:
            return apology("Must provide a search term", 400)

        #next I am going to create the API Search
            #search_type is in our search.html
        if search_type == "character":
            #we set result equal to the helper function for searching characters and pass in our users query
            result = search_character(query)
            #if the query could not fund anything
            if not result:
                return apology(f"No pirate named '{query}' in our logs!", 404)
            #if no issues we will return the user to our search_user.html page which shows character/characters
                #we set the character equal to the result which is the users query for a character
            return render_template("search_result.html", character=result)

        #next we define the user search which will have to utilize our SQL
        elif search_type == "user":
            #we will need to search our SQL users table
            #i pass in the query of the user
            user_results = db.execute("SELECT id, username FROM users WHERE username LIKE ?", f"%{query}%")
            #perform user validation should a user not be found within the db
            if not user_results:
                return apology(f"No Captain named '{query}' found!", 404)
            #if there is no issue then we will return the user to the user_results.html
                #we set user to user_results
            return render_template("user_results.html", users=user_results)

        #the final search type is for a crew
        elif search_type == "crew":
            #we need to search our SQL 'crews' table
            crew_results = db.execute("SELECT * FROM crews WHERE crew_name LIKE ?", f"%{query}%")
            #need to perform validation should a crew not be found within our db
            if not crew_results:
                return apology(f"The '{query}' hasn't set sail yet!", 404)
            #how if it does return a crew result then it means something was found and we will take the user to our crew_results html page
            return render_template("crew_results.html", crews=crew_results)
    #if it is just a GET request then we will only show the page to the user
    return render_template("search.html")


#Next I am going to create the function which will help to join to find every member that belongs to a specific fleet
@app.route("/crew/<int:crew_id>")
@login_required
def crew_view(crew_id):
# 1. Pull the crew info
    crew = db.execute("SELECT * FROM crews WHERE id = ?", crew_id)

    # If the crew doesn't exist (manual URL entry error)
    if not crew:
        return apology("That fleet has been lost at sea!", 404)

    # 2. Pull the roster of members
    # We join the users table with memberships to get actual names
    members = db.execute("""
        SELECT users.username, users.id
        FROM users
        JOIN memberships ON users.id = memberships.user_id
        WHERE memberships.crew_id = ?
    """, crew_id)

    # 3. Render the page
    print(f"DEBUG - Crew Dictionary: {crew[0]}")
    return render_template("crew_view.html", crew=crew[0], members=members)

#I need to create a function where if a user is within the crew view and
#they select a fictional character, it will direct them to the characters profile
@app.route("/character/<int:char_id>")
@login_required
def character_profile(char_id):
    response = requests.get(f"https://api.api-onepiece.com/v1/characters/{char_id}",
                            timeout=5)
    if response.status_code != 200:
        return apology("Character not found!", 404)

    char_data = response.json()

    # Clean the Bounty: Change dots to commas and add the ฿ symbol
    if char_data.get("bounty"):
        char_data["formatted_bounty"] = "฿ " + char_data["bounty"].replace(".", ",")
    else:
        char_data["formatted_bounty"] = "Unknown"

    # Clean the Age: Change "ans" to "Years"
    if char_data.get("age"):
        char_data["age"] = char_data["age"].replace("ans", "Years")

    return render_template("search_result.html", character=char_data)

@app.route("/profile/<int:user_id>")
@login_required
def profile_view(user_id):
    # 1. Retrieve the Captain's basic info first
    user_rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if not user_rows:
        return apology("Captain not found", 404)
    captain = user_rows[0]

    # 2. Handle Watchlog & API Progress
    total_episodes = get_total_episodes()
    watched_data = db.execute("SELECT COUNT(*) as count FROM watchlog WHERE user_id = ?", user_id)
    watched_count = watched_data[0]["count"]

    # Calculate progress and bounty
    progress_percent = (watched_count / total_episodes * 100) if total_episodes > 0 else 0
    current_bounty = watched_count * 1000000

    # Sync the bounty back to the database
    db.execute("UPDATE users SET bounty = ? WHERE id = ?", current_bounty, user_id)

    # 3. Handle Fleet Logic (Owned Crew vs Alliances)
    # Owned: Where the user is the founder
    owned_crew = db.execute("SELECT * FROM crews WHERE founder_id = ?", user_id)

    # Alliances: Where the user is a member but NOT the founder
    fleet_query = """
        SELECT crews.id, crews.crew_name
        FROM crews
        JOIN memberships ON crews.id = memberships.crew_id
        WHERE memberships.user_id = ?
        AND (crews.founder_id != ? OR crews.founder_id IS NULL)
    """
    alliances = db.execute(fleet_query, user_id, user_id)

    # 4. Get the specific reviews for the Watchlog tab
    watchlog_entries = db.execute("""
        SELECT episode_number, rating, comment, timestamp
        FROM watchlog WHERE user_id = ?
        ORDER BY episode_number DESC
    """, user_id)

    # ONE return to rule them all
    return render_template("profile_view.html",
                           captain=captain,
                           progress=round(progress_percent, 1),
                           total_eps=total_episodes,
                           watched=watched_count,
                           owned_crew=owned_crew[0] if owned_crew else None,
                           alliances=alliances,
                           watchlog=watchlog_entries)


@app.route("/edit_profile/", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        role = request.form.get("role")
        bio = request.form.get("bio")
        db.execute("UPDATE users SET role = ?, bio = ? WHERE id = ?", role, bio, session["user_id"])
        flash("Captain's Log Updated!")
        return redirect(f"/profile/{session['user_id']}")

    # GET: Fetch data to pre-fill the form
    user_data = db.execute("SELECT id, username, role, bio FROM users WHERE id = ?", session["user_id"])

    # We use 'user' here because your edit_profile.html uses {{ user.role }}
    return render_template("edit_profile.html", user=user_data[0])

def get_character_data(name):
    url = "https://onepieceql.up.railway.app/graphql"

    # This query asks for specific fields based on the character's name
    query = """
    {
      character(filter: {englishName: "%s"}) {
        englishName
        avatarSrc
        bounty
        age
      }
    }
    """ % name

    try:
        response = requests.post(url, json={'query': query}, timeout=5)
        if response.status_code == 200:
            result = response.json()
            return result['data']['character']
    except Exception as e:
        print(f"API Error: {e}")
    return None

def get_avatar_from_ql(name):
    url = "https://onepieceql.up.railway.app/graphql"

    # We search by englishName to find the avatarSrc
    query = """
    {
      character(filter: {englishName: "%s"}) {
        avatarSrc
      }
    }
    """ % name

    try:
        response = requests.post(url, json={'query': query}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Navigate the JSON layers to get the image link
            char = data.get('data', {}).get('character')
            return char.get('avatarSrc') if char else None
    except Exception as e:
        print(f"GraphQL Error: {e}")
    return None

@app.route("/crew/<int:crew_id>/join", methods=["POST"])
@login_required
def join_crew(crew_id):
    user_id = session["user_id"]

    # Check if crew exists
    crew = db.execute("SELECT * FROM crews WHERE id = ?", crew_id)
    if not crew:
        return apology("Crew not found", 404)

    # Check if already a member
    existing = db.execute(
        "SELECT * FROM memberships WHERE user_id = ? AND crew_id = ?",
        user_id, crew_id
    )
    if existing:
        flash("You're already part of this crew!")
        return redirect(f"/crew/{crew_id}")

    # Add membership
    db.execute(
        "INSERT INTO memberships (user_id, crew_id) VALUES (?, ?)",
        user_id, crew_id
    )
    flash(f"Successfully joined {crew[0]['crew_name']}!")
    return redirect(f"/crew/{crew_id}")



# Add this route to your app.py (after the edit_profile route)

@app.route("/log_episode", methods=["GET", "POST"])
@login_required
def log_episode():
    """Allow users to log episodes they've watched with ratings and comments"""

    if request.method == "POST":
        # Get form data
        episode_number = request.form.get("episode_number")
        rating = request.form.get("rating")
        comment = request.form.get("comment")

        # Validation
        if not episode_number:
            return apology("Must provide episode number", 400)

        if not rating:
            return apology("Must provide a rating", 400)

        # Convert to integers and validate
        try:
            episode_number = int(episode_number)
            rating = int(rating)
        except ValueError:
            return apology("Episode number and rating must be numbers", 400)

        # Validate episode number (must be positive)
        if episode_number < 1:
            return apology("Episode number must be at least 1", 400)

        # Validate rating (1-10)
        if rating < 1 or rating > 10:
            return apology("Rating must be between 1 and 10", 400)

        # Check if user already logged this episode
        existing = db.execute(
            "SELECT * FROM watchlog WHERE user_id = ? AND episode_number = ?",
            session["user_id"], episode_number
        )

        if existing:
            # Update existing entry
            db.execute(
                "UPDATE watchlog SET rating = ?, comment = ?, timestamp = CURRENT_TIMESTAMP WHERE user_id = ? AND episode_number = ?",
                rating, comment, session["user_id"], episode_number
            )
            flash(f"Updated your log for Episode {episode_number}!")
        else:
            # Insert new entry
            db.execute(
                "INSERT INTO watchlog (user_id, episode_number, rating, comment) VALUES (?, ?, ?, ?)",
                session["user_id"], episode_number, rating, comment
            )
            flash(f"Successfully logged Episode {episode_number}!")

        # Redirect back to profile
        return redirect(f"/profile/{session['user_id']}")

    # GET request - show the form
    # Get total episodes for validation
    total_eps = get_total_episodes()

    # Get episodes already watched (to show what's left)
    watched = db.execute(
        "SELECT episode_number FROM watchlog WHERE user_id = ? ORDER BY episode_number",
        session["user_id"]
    )
    watched_numbers = [ep["episode_number"] for ep in watched]

    return render_template("log_episode.html",
                         total_episodes=total_eps,
                         watched_episodes=watched_numbers)
