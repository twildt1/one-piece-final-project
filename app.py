import os
import requests

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, search_character, get_total_episodes, get_episode_title
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# here I am going to configure my cs50 library to connect to my db
db = SQL("sqlite:///one_piece.db")


@app.route("/")
def index():
    # if my user does not provide a user id
    if not session.get("user_id"):
        # redirect them to the homepage
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
            # if it does not exist then we will return the apology helper and provide a message to the user with a 403 error
            return apology("invalid username and/or password", 403)

        # however, if the user passes the validation they will move on and the user id will be saved
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
    # we need to get the username and password and as well as the confirmation
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    # now we have to validate if our user provides a username, password, and if the password and confirmation match
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
    # if they pass all of the validations then we create a variable named hash which is equal to the generate_password_hash
    # which was imported and used within the finance hw to hash a password, we then pass in the password variable into that password so that our password will be hashed
    hash = generate_password_hash(password)

    # next we insert our new user
    # see that we pass in the hash and not the password (plaintext)
    user_id = db.execute(
        "INSERT INTO users (username, hash) VALUES (?, ?)",
        username,
        hash
    )

    # for simplicity sake the user should automatically be logged in after registering
    session["user_id"] = user_id

    # finally, we will redirect the user back to the home page
    return redirect("/")

# Next i am going to create my search function


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        # this is coming from <input name="query" type="text" class="form-control form-control-lg" placeholder="Search for a pirate, captain, or crew!" required autofocus>
        query = request.form.get("query")
        # this is coming from <input class="form-check-input" type="radio" name="search_type" id="char" value="character" checked>
        # there are four options we defined within this name of search_type which is pirate, user, and fleet
        search_type = request.form.get("search_type")

        # should the user not provide anything within the search
        if not query:
            # return apology and a message
            return apology("Must provide a search term", 400)

        # character search logic
        if search_type == "character":
            # 1. Get basic stats
            # we call the search-character helped function which is used to access the API
            # we pass in our query into it
            result = search_character(query)

            # should no character be returned
            if not result:
                return apology(f"No pirate named '{query}' in our logs!", 404)

            # The API passed in the age as "ans" for some reason and to clean the "Age" (Change 'ans' to 'Years')
            if result.get("age") and "ans" in str(result["age"]):
                # use the replace method
                result["age"] = str(result["age"]).replace("ans", "Years")

            # I render the search_result and set character equal to the results that we get
            return render_template("search_result.html", character=result)

        # User Search logic
        # this is used when our search type in equal to user
        elif search_type == "user":
            # for the search for our users we need to execute within our db.
            # we need to select the id and username from our users table
            user_results = db.execute(
                "SELECT id, username FROM users WHERE username LIKE ?", f"%{query}%")
            if not user_results:
                # if we cannnot find the user we return an apology and pass in the user query.
                return apology(f"No Captain named '{query}' found!", 404)
            # however if the user was found we will render the template for user results, which is the HTMl that displays the return
            # and the then set users equal to the user_results
            return render_template("user_results.html", users=user_results)

        # Crew Search
        elif search_type == "crew":
            # we will need to perform an execution within our database and will search from the crews table for the crew name
            # we use a like as it will search for results that are similar to the query
            crew_results = db.execute("SELECT * FROM crews WHERE crew_name LIKE ?", f"%{query}%")
            # however, if no crew is found we will pass in the apology helper function
            if not crew_results:
                return apology(f"The '{query}' hasn't set sail yet!", 404)
            # however, if a crew is found we will render crew_results and we set crews equal to crew_results
            return render_template("crew_results.html", crews=crew_results)

    return render_template("search.html")


# Next I am going to create the function which will help to join to find every member that belongs to a specific fleet
# as specified within crew_results the href for the crew_view is /crew/crew_id
@app.route("/crew/<int:crew_id>")
@login_required
# I pass in the crew_id into the crew_view function
def crew_view(crew_id):
    # 1. Get Crew Details
    crew = db.execute("SELECT * FROM crews WHERE id = ?", crew_id)
    # if the crew is not found then I will pass in the apology helper and a message with a 404 error
    if not crew:
        return apology("That fleet has been lost at sea!", 404)

    # Get Real Users (Unlimited)
    # Joins 'users' table with 'memberships'
    # within the memberships table I have the user_id and crew_id as FK that allow linkage to the crews and users tables
    members = db.execute("""
        SELECT users.username, users.id, memberships.role, users.bounty
        FROM users
        JOIN memberships ON users.id = memberships.user_id
        WHERE memberships.crew_id = ?
    """, crew_id)

    # Get Fictional Characters (Limited to 15)
    # to provide linkage to the characters and crew, I have the crew_id as a FK within the crew_characters table
    characters = db.execute("SELECT * FROM crew_characters WHERE crew_id = ?", crew_id)

    # Calculate Total Bounty (Users + Characters)
    # we set to 0 to start
    total_bounty = 0

    # Add User Bounties
    for m in members:
        total_bounty += m["bounty"]

    # Add Character Bounties (Clean up string "1,500,000" -> int)
    for c in characters:
        if c["bounty"]:
            # Remove symbols, dots, commas so we can do math
            clean_val = str(c["bounty"]).replace(",", "").replace(".", "").replace("฿", "").strip()
            if clean_val.isdigit():
                total_bounty += int(clean_val)
    # this will make the total_bpunty variable add up the user and character bountys to arrive at the total bountys for that crew as a whole

    # we then render the crew_view page and set the crew equal to the returned query, members to members, characters to characters, and total_bounty to total_bounty
    return render_template("crew_view.html",
                           crew=crew[0],
                           members=members,
                           characters=characters,
                           total_bounty=f"{total_bounty:,}")
    # The ":," adds commas back to the number (e.g. 1,000,000)


@app.route("/profile/<int:user_id>")
@login_required
def profile_view(user_id):
    # Retrieve the Captain's basic info first
    user_rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    # perform validation
    if not user_rows:
        return apology("Captain not found", 404)
    # if the user is found we set the captain to the first result found
    captain = user_rows[0]

    # Handle Watchlog & API Progress
    # call the helper function of get_total_episodes which utilizes the api
    total_episodes = get_total_episodes()
    # to allow a relationship between the users table and the watchlog table, I set user_id as a FK within the watchlog table
    watched_data = db.execute("SELECT COUNT(*) as count FROM watchlog WHERE user_id = ?", user_id)
    # Pass in that count as this is the # of entries with that user_id in the table means that is how many eps they have watched of the show
    watched_count = watched_data[0]["count"]

    # Calculate progress and bounty
    # this is used to create a progress bar show the users progress of watching the show
    progress_percent = (watched_count / total_episodes * 100) if total_episodes > 0 else 0
    # I wanted to create a function that calculates the user bounty to the # of eps they have watched
    # times 1000000
    current_bounty = watched_count * 1000000

    # Sync the bounty back to the database
    # I then need to pass this into the SQL Db so that it is saved
    # pass in the current_bounty variable as well as the user_id
    db.execute("UPDATE users SET bounty = ? WHERE id = ?", current_bounty, user_id)

    # Handle Fleet Logic (Owned Crew vs Alliances)
    # Owned: Where the user is the founder
    owned_crew = db.execute("SELECT * FROM crews WHERE founder_id = ?", user_id)

    # Alliances: Where the user is a member but NOT the founder. Need to work on the structure of this in future implementation of the project (after CS50).
    fleet_query = """
        SELECT crews.id, crews.crew_name
        FROM crews
        JOIN memberships ON crews.id = memberships.crew_id
        WHERE memberships.user_id = ?
        AND (crews.founder_id != ? OR crews.founder_id IS NULL)
    """
    # I then set alliances to that query variable and pass in the user_id
    alliances = db.execute(fleet_query, user_id, user_id)

    # Get the specific reviews for the Watchlog tab
    watchlog_entries = db.execute("""
        SELECT episode_number, rating, comment, timestamp, title
        FROM watchlog WHERE user_id = ?
        ORDER BY episode_number DESC
    """, user_id)

    # ONE return to rule them all
    # I pass in all of the functions I has just created. I use the round method to help formatation.
    return render_template("profile_view.html",
                           captain=captain,
                           progress=round(progress_percent, 1),
                           total_eps=total_episodes,
                           watched=watched_count,
                           owned_crew=owned_crew[0] if owned_crew else None,
                           alliances=alliances,
                           watchlog=watchlog_entries)


@app.route("/my_profile_edit", methods=["GET", "POST"], strict_slashes=False)
@login_required
def edit_profile():
    # if the request methof is POST then we will get the role, bio, an and update the role and bio within the db with request.form.get.
    # if the request update works then we will run a pop up msg
    if request.method == "POST":
        role = request.form.get("role")
        bio = request.form.get("bio")
        db.execute("UPDATE users SET role = ?, bio = ? WHERE id = ?", role, bio, session["user_id"])
        flash("Captain's Log Updated!")
        # then we will redirct them back to their profile
        return redirect(f"/profile/{session['user_id']}")

    # GET: Fetch data to pre-fill the form
    user_data = db.execute(
        "SELECT id, username, role, bio FROM users WHERE id = ?", session["user_id"])

    # We use 'user' here because my edit_profile.html uses {{ user.role }}
    return render_template("edit_profile.html", user=user_data[0])


def get_character_data(name):
    # pass in one of the one piece API's.
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
    # the % acts as a placeholder value to pass these values into name?

    # the script will try to connect to the API for 5 seconds and then if it does not it will return an API error and nothing within the webstie
    try:
        response = requests.post(url, json={'query': query}, timeout=5)
        if response.status_code == 200:
            result = response.json()
            return result['data']['character']
    except Exception as e:
        print(f"API Error: {e}")
    return None


@app.route("/log_episode", methods=["GET", "POST"])
@login_required
# this function is used to login episodes
def log_episode():
    if request.method == "POST":
        # Get form data
        start_ep = request.form.get("start_episode")
        end_ep = request.form.get("end_episode")
        rating = request.form.get("rating")
        comment = request.form.get("comment")

        # Validation
        # if they do not provide an episode OR rating
        if not start_ep or not rating:
            return apology("Must provide episode and rating", 400)

        # the user must pass in the episodes as #'s
        try:
            start_ep = int(start_ep)
            # If end_ep is empty, user is just logging one episode
            end_ep = int(end_ep) if end_ep else start_ep
            rating = int(rating)
        except ValueError:
            return apology("Episode numbers must be integers", 400)

        # case in which the user were to add the start eps as 100 and the end eps of 0
        if start_ep > end_ep:
            return apology("Start episode cannot be higher than End episode", 400)

        # LOOP: Iterate through the range of episodes
        # range is exclusive at the end, so we add +1
        for ep_num in range(start_ep, end_ep + 1):

            # Fetch Title (Using our new helper)
            title = get_episode_title(ep_num)

            # Check if exists
            existing = db.execute(
                "SELECT * FROM watchlog WHERE user_id = ? AND episode_number = ?",
                session["user_id"], ep_num
            )

            # if the data exist then we will update the watchlog and provide the users data within the db
            # this means that the user already provided a rating for the epsidoe but wants to overwrite their review
            if existing:
                db.execute("""
                    UPDATE watchlog
                    SET rating = ?, comment = ?, title = ?, timestamp = CURRENT_TIMESTAMP
                    WHERE user_id = ? AND episode_number = ?
                """, rating, comment, title, session["user_id"], ep_num)
            # else it means the user is defining/inserting a review for an episode(s) they have no watched
            else:
                db.execute("""
                    INSERT INTO watchlog (user_id, episode_number, rating, comment, title)
                    VALUES (?, ?, ?, ?, ?)
                """, session["user_id"], ep_num, rating, comment, title)

        flash(f"Successfully logged episodes {start_ep} to {end_ep}!")
        return redirect(f"/profile/{session['user_id']}")

    # GET REQUEST
    # we call the helper function of get_total_episdoes
    total_eps = get_total_episodes()
    watched = db.execute(
        "SELECT episode_number FROM watchlog WHERE user_id = ? ORDER BY episode_number",
        session["user_id"]
    )
    # create a for loop to count the # of episodes which a user has watched
    watched_numbers = [ep["episode_number"] for ep in watched]

    # we render our log eps page and set total_episodes and watched_episodes
    return render_template("log_episode.html",
                           total_episodes=total_eps,
                           watched_episodes=watched_numbers)

# I am going to add a delete feature that allows a user to delete an episode entry


@app.route("/delete_log", methods=["POST"])
@login_required
def delete_log():
    # Get the episode number from the hidden form input
    episode_number = request.form.get("episode_number")

    if episode_number:
        db.execute("DELETE FROM watchlog WHERE user_id = ? AND episode_number = ?",
                   session["user_id"], episode_number)
        flash(f"Removed Episode {episode_number} from your log.")

    return redirect(f"/profile/{session['user_id']}")


# I am going to create the function that allows a user to add characters to their crew
# I am setting a limit of 15 to the fictional characters a user can add to their crew/
@app.route("/add_character_crew", methods=["POST"])
@login_required
def add_character_crew():
    # 1. Get Data
    char_name = request.form.get("name")
    char_id = request.form.get("id")
    char_bounty = request.form.get("bounty")

    # Debug print to check if data is arriving
    print(f"DEBUG: Adding {char_name} (ID: {char_id})")

    # 2. Get User's Crew
    # captain ID from crews table is related to the users and invitations table
    user_crew = db.execute(
        "SELECT id, crew_name FROM crews WHERE captain_id = ?", session["user_id"])

    if not user_crew:
        flash("You must be a Captain to recruit!")
        return redirect("/create_crew")

    crew_id = user_crew[0]["id"]
    crew_name = user_crew[0]["crew_name"]

    # 3. Check Limit (Max 15)
    count_data = db.execute(
        "SELECT COUNT(*) as count FROM crew_characters WHERE crew_id = ?", crew_id)
    if count_data[0]["count"] >= 15:
        flash(f"Your crew is full! (Max 15 Fictional Characters)", "error")
        return redirect(f"/crew/{crew_id}")

    # 4. Insert with Error Handling
    try:
        # We try to insert. If it fails due to UNIQUE constraint, the 'except' block runs.
        db.execute("""
            INSERT INTO crew_characters (crew_id, api_id, name, bounty)
            VALUES (?, ?, ?, ?)
        """, crew_id, char_id, char_name, char_bounty)

        flash(f"{char_name} has joined {crew_name}!")

    except ValueError:
        # This catches the "UNIQUE constraint failed" error safely
        flash(f"{char_name} is already in your crew!", "error")
    except Exception as e:
        # This catches any other DB errors
        print(f"DATABASE ERROR: {e}")
        flash("An error occurred while adding the pirate.", "error")

    return redirect(f"/crew/{crew_id}")


#this function was created with assistance from Gemini
@app.route("/my_crew")
@login_required
def my_crew():
    # 1. PRIORITY CHECK: Do I own a crew? (Am I the Captain?)
    # We query the 'crews' table directly to see if the user is a founder/captain
    owned_crew = db.execute("SELECT id FROM crews WHERE captain_id = ?", session["user_id"])

    if owned_crew:
        # If I am a Captain, ALWAYS take me to my own ship first
        return redirect(f"/crew/{owned_crew[0]['id']}")

    # 2. SECONDARY CHECK: Am I just a member of someone else's crew?
    # If the first check failed, THEN we look at the general memberships table
    membership = db.execute("SELECT crew_id FROM memberships WHERE user_id = ?", session["user_id"])

    if membership:
        # If I don't own a ship, take me to the one I joined
        return redirect(f"/crew/{membership[0]['crew_id']}")

    # 3. FALLBACK: I have no crew at all -> Create one
    return redirect("/create_crew")


#this function was created with assistance from Gemini
@app.route("/create_crew", methods=["GET", "POST"])
@login_required
def create_crew():
    # 1. Handle Form Submission
    if request.method == "POST":
        crew_name = request.form.get("crew_name")
        motto = request.form.get("motto")

        if not crew_name:
            return apology("Your ship needs a name!", 400)

        # Check if crew name is taken
        existing = db.execute("SELECT * FROM crews WHERE crew_name = ?", crew_name)
        if existing:
            return apology("That crew name is already taken!", 400)

        # 2. Insert the Crew into the Database
        # We assume the user creating it is the Captain
        crew_id = db.execute(
            "INSERT INTO crews (captain_id, founder_id, crew_name, motto) VALUES (?, ?, ?, ?)",
            session["user_id"], session["user_id"], crew_name, motto
        )

        # 3. Automatically make the user the 'Captain' in the memberships table
        db.execute(
            "INSERT INTO memberships (user_id, crew_id, role) VALUES (?, ?, 'Captain')",
            session["user_id"], crew_id
        )

        flash(f"The {crew_name} has set sail!")
        return redirect(f"/crew/{crew_id}")

    # 2. Handle GET Request (Show the form)
    return render_template("create_crew.html")


# --- INVITATION ROUTES ---

#this function was created with assistance from Gemini
@app.route("/notifications")
@login_required
def notifications():
    user_id = session["user_id"]

    # 1. Get RECEIVED Requests (People inviting ME)
    received = db.execute("""
        SELECT invitations.id, invitations.status, crews.crew_name, users.username as sender_name
        FROM invitations
        JOIN crews ON invitations.crew_id = crews.id
        JOIN users ON invitations.sender_id = users.id
        WHERE invitations.receiver_id = ?
        ORDER BY invitations.timestamp DESC
    """, user_id)

    # 2. Get SENT Requests (Who I invited)
    sent = db.execute("""
        SELECT invitations.status, users.username as receiver_name, crews.crew_name
        FROM invitations
        JOIN users ON invitations.receiver_id = users.id
        JOIN crews ON invitations.crew_id = crews.id
        WHERE invitations.sender_id = ?
        ORDER BY invitations.timestamp DESC
    """, user_id)

    return render_template("notifications.html", received=received, sent=sent)


#this function was created with assistance from Gemini
@app.route("/invite_user", methods=["POST"])
@login_required
def invite_user():
    receiver_id = request.form.get("receiver_id")

    # 1. Check if I have a crew
    my_crew = db.execute("SELECT id, crew_name FROM crews WHERE captain_id = ?", session["user_id"])
    if not my_crew:
        flash("You must be a Captain to invite people!")
        return redirect("/create_crew")

    crew_id = my_crew[0]["id"]

    # 2. Check if user is ALREADY in the crew
    is_member = db.execute(
        "SELECT * FROM memberships WHERE user_id = ? AND crew_id = ?", receiver_id, crew_id)
    if is_member:
        flash("That pirate is already in your crew!")
        return redirect("/search")

    # 3. Check if invite ALREADY exists (Pending)
    existing_invite = db.execute("""
        SELECT * FROM invitations
        WHERE receiver_id = ? AND crew_id = ? AND status = 'pending'
    """, receiver_id, crew_id)

    if existing_invite:
        flash("You already sent an invite to this user.")
        return redirect("/search")

    # 4. Send Invite
    db.execute("""
        INSERT INTO invitations (sender_id, receiver_id, crew_id, status)
        VALUES (?, ?, ?, 'pending')
    """, session["user_id"], receiver_id, crew_id)

    flash("Invitation sent!")
    return redirect("/notifications")


#this function was created with assistance from Gemini
@app.route("/respond_invite", methods=["POST"])
@login_required
def respond_invite():
    invite_id = request.form.get("invite_id")
    action = request.form.get("action")  # 'accept' or 'reject'

    # Get invite details
    invite = db.execute("SELECT * FROM invitations WHERE id = ?", invite_id)
    if not invite:
        return apology("Invitation not found", 404)

    if action == "accept":
        # 1. Add to memberships
        db.execute("INSERT INTO memberships (user_id, crew_id) VALUES (?, ?)",
                   session["user_id"], invite[0]["crew_id"])

        # 2. Update Invite Status
        db.execute("UPDATE invitations SET status = 'accepted' WHERE id = ?", invite_id)
        flash("You have joined the crew!")

    elif action == "reject":
        db.execute("UPDATE invitations SET status = 'rejected' WHERE id = ?", invite_id)
        flash("Invitation rejected.")

    return redirect("/notifications")
