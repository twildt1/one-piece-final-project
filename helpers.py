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
    #should there be an error with our query search within the API
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
        # NOTE: I removed the "/count" from the URL so we get the list of all episodes
        # This ensures len() counts the actual list items
        response = requests.get("https://api.api-onepiece.com/v2/episodes/en")

        #means the URL was able to connect
        if response.status_code == 200:
            episodes = response.json()
            #will return the count of the # of eps which there are currently as they come out weekly (for now).
            return len(episodes)
    except Exception as e:
        print(f"Error fetching API: {e}")

    # Fallback number
    #should it not work, I'll return the static # of eps that there are as of 12/28
    return 1155


#I am going to add a helper function that will search the Episode name
def get_episode_title(episode_number):
    """Fetch the title of a specific episode from the API with DEBUGGING"""
    try:
        # Note: We are trying to fetch by ID/Number.
        # If this fails, it's likely because '1015' is the Episode Number, but the API expects ID '5432'
        url = f"https://api.api-onepiece.com/v2/episodes/en/{episode_number}"

        print(f"--- DEBUG: Fetching {url} ---") # Check your terminal for this!

        response = requests.get(url, timeout=3)
        print(f"--- DEBUG: Status Code: {response.status_code} ---")

        if response.status_code == 200:
            data = response.json()
            print(f"--- DEBUG: JSON Data: {data} ---") # See what the API actually returned

            # The API might return the title as "title", "english_title", or something else
            return data.get("title", f"Episode {episode_number}")

    except Exception as e:
        print(f"--- DEBUG: Error fetching title: {e} ---")

    return f"Episode {episode_number}"

