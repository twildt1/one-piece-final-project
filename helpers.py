import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

#we pass the name into the function, which is from our python and our HTML
def search_character(name):
    """this helper function is going to helps find a character that a user searchs for
    via the OP API"""
    url = f"https://api.api-onepiece.com/v2/characters/en/search?name={name}"

    #we try to access the API first
    try:
        #use a get call to the url
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for HTTP error responses
        data = response.json()

        #if the API were to return a list of matching characters
        if not data or len(data) == 0:
            return None
        #we will take the first match found
        char = data[0]

        #we need to handle the fruit nesting more carefully as it is outside of the main data structure within the API.
            #fruit is a dictionary inside of another dictionary
            #therefore, we set fruit_info to char.get("fruit") so we can use it to access information specific to the devil fruit within the API
        fruit_info = char.get("fruit")

        #we will return the characters information
        return {
            "id": char.get("id"),
            "name": char.get("name"),
            "bounty": char.get("bounty", "Unknown"), #will return unknown if not known
            "age": char.get("age", "Unknown"),
            #if the fruits info exist, get the name/type, otherwise we will return that they are not a devil fruit user
            "fruit_name": fruit_info.get("name", "None") if fruit_info else "No Devil Fruit",
            "fruit_type": fruit_info.get("type", "None") if fruit_info else "No Devil Fruit"
        }
    except (requests.RequestException, ValueError, KeyError):
        return None

def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code

#I am adding a helped function that will search the OP API for the total episodes
def get_total_episodes():
    try:
        # Fetching all episodes from the API
        response = requests.get("https://api.api-onepiece.com/v2/episodes/en/count")
        if response.status_code == 200:
            episodes = response.json()
            return len(episodes) # The number of items in the list is the total count
    except Exception as e:
        print(f"Error fetching API: {e}")

    # Fallback number if API fails (so your site doesn't crash)
    return 1116


#I am making a helper function to query an API for a characters picture
import requests

def get_character_images():
    url = "https://onepieceql.up.railway.app/graphql"
    query = "{ characters { englishName avatarSrc bounty } }"

    response = requests.post(url, json={'query': query})
    if response.status_code == 200:
        data = response.json()
        return data['data']['characters']
    return []
