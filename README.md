GRAND LINE LOG

Video Demo: [INSERT YOUR YOUTUBE LINK HERE]

Description:

Grand Line Log is a web-based fleet management and community application designed specifically for fans of One Piece. In many massive online communities, managing the hierarchy of players, from individual recruits to squad leaders, is a chaotic process often handled in spreadsheets or disconnected Discord channels. This project solves that problem by visualizing the relationship between individual users, their immediate Crews, and their progress through the series.

The application serves as a comprehensive "Minimum Viable Product" (MVP) for a larger social platform. It allows users to register for secure accounts, log their watch history of the anime, and "gamify" their experience by earning a Bounty (score) based on the number of episodes watched. A core feature of the application is the Crew System, where users can form their own pirate crews, invite other real-world users via a notification system, and even recruit fictional characters from the One Piece universe into their ranks.

Unlike static wiki pages, Grand Line Log is dynamic. A user’s standing in the community is determined by their activity. The application bridges the gap between a personal tracker (like MyAnimeList) and a guild management tool (like those found in MMOs), wrapped in a thematic interface that immerses the user in the world of pirates.

Key Features:

Dynamic Search Engine: Users can filter searches by "Character," "User," or "Crew." The character search utilizes the One Piece API to return specific character profiles. If a user searches for "King," the system intelligently resolves this to "Kingbaum" or the most likely match, returning vital stats like Age and Devil Fruit powers.

Hybrid Roster System: A unique feature of this project is the ability to mix "Real Users" and "NPCs" (Non-Player Characters) in a single crew view. Captains can recruit up to 15 fictional characters via the API, which coexist alongside real user members in the database.

Gamification (Bounty System): The application automatically calculates a user's "Bounty" based on their watch logs. Every episode logged increases their value, which contributes to the total Crew Bounty, creating a competitive leaderboard effect among different crews.

Notification Center: A robust invitation system allows Captains to send requests to users. The "Alerts" tab handles the state of these invites (Pending, Accepted, Rejected) in real-time.

File Overview:

The project is built using Python, Flask, and SQL, and is structured into the following key files:

app.py: The core controller of the application. It initializes the Flask app, configures the filesystem-based session, and contains all 16+ route definitions. This file handles the complex logic for:

/search: Acts as a traffic controller, differentiating between API calls (for characters) and internal SQL queries (for users/crews). It handles POST requests to filter results dynamically.

/crew/<id>: Performs a complex aggregation. It queries the users table for real members and the crew_characters table for NPC recruits, then merges them into a single list to render the roster. It also calculates the Total Bounty on the fly.

/profile/<id>: Handles the user's personal dashboard. It calculates their progress percentage through the anime, updates their dynamic bounty in the database, and fetches their watch history.

/log_episode: Allows users to batch-log episodes (e.g., "Episodes 1 to 100") using a loop, saving them from manual entry fatigue.

helpers.py: This utility file keeps the main controller clean. It contains the @login_required decorator, which ensures sensitive routes (like editing profiles or managing crews) are protected from anonymous access. It also contains the search_character() function, which encapsulates the logic for sending requests to the external One Piece API and parsing the JSON response.

project.db: The SQLite database engine. It features a relational schema linking users, crews, memberships, watchlog, and invitations.

Templates:

The user interface is powered by Jinja2 templates extending a common layout:

layout.html: The master template containing the navigation bar (Home, Search, My Crew, Alerts, Profile) and footer. It uses Jinja2 blocks to ensure a consistent look across all pages.

index.html: The startup page of the website. It directs new users to register and returning captains to their dashboard.

register.html: A secure form used specifically to register a user. It sends their password to the database via a POST method; crucially, the password is hashed in app.py before storage to ensure security.

login.html: Allows the user to log in. Like registration, it utilizes the POST method and compares the provided password against the hashed value in the database.

apology.html: Renders error notifications to the user (e.g., 400 or 404 errors), displaying a custom "Confused Luffy" image served from the static/ folder.

create_crew.html: Displays the crew creation form. This is the first step for a user who has just registered and wants to become a Captain.

crew_view.html: A complex template that shows crew details such as name, motto, and summed bounty. It uses Jinja loops to display two distinct lists (Real Members vs. NPC Recruits) and uses conditional logic to show
administrative buttons only if the viewer is the Captain.

search.html: The central search hub containing options to filter by Characters, Users, or Fleets (Crews).

search_result.html: Specifically used to display Character information. It utilizes data pulled from the API and provides a link to the One Piece Fandom wiki for additional lore.

user_results.html: Displays a list of users that match a specific search query, allowing for partial matches.

crew_results.html: The result page for crew searches. It provides a button allowing the user to "View Crew," which redirects them to the detailed crew_view.html page.

profile_view.html: The most complex visualization page. It displays the user's bio, rank, and watch statistics.

notifications.html: Displays two tables: one for received invites (with Accept/Reject forms) and one for sent invites (to track outgoing requests).

Static Assets:

static/styles.css: Custom CSS used to override standard Bootstrap components. I used this to give the application a nautical/anime-inspired aesthetic, specifically customizing the card backgrounds, button colors, and font weights to match the project's theme.


Design Choices:
1. The "Hybrid" Database Approach One of the biggest challenges was deciding how to handle "Fictional Characters" versus "Real Users." I debated creating a single members table for both. However, I chose to keep them separate (users table vs crew_characters table) because real users require authentication data (passwords, sessions) while NPCs only need static data (names, images). I then merged these two data streams in the crew_view route. This design choice keeps the authentication system secure while still allowing for a unified user interface.
2. API Integration Strategy I utilized multiple sources for data: the One Piece API (for raw data like names and bounties) and the One Piece Wiki (for deep dives). I decided not to host all character data locally because the source material is vast and constantly changing. By relying on the API for searches (e.g., matching "King" to "Kingbaum") and linking out to the Wiki for detailed biographies, I kept my database lightweight and performance-focused. This ensures that my application remains scalable without needing to scrape and store thousands of wiki pages.
3. State-Based Invitation System For the "Crew Invite" feature, I implemented a state-machine logic using an invitations table. Instead of instantly adding a user to a crew upon invite, the system creates a "Pending" record. This was a deliberate choice to prevent spam and ensure consent. The respond_invite route checks this state before modifying the memberships table, ensuring that a user cannot be forced into a crew without their action.
4. Future Roadmap: Fleet Hierarchies While the current version supports independent Crews, the database schema was architected to support Fleet Alliances in the future. I deliberately included a self-referencing structure in the database design to allow a Crew to "join" another Crew. This would require a recursive SQL query (using Common Table Expressions) to link a "Child Crew" to a "Parent Crew." This structure will allow for massive organizations (Grand Fleets) where a single "Flagship" crew has authority over multiple sub-crews. The "Alerts" system is already built to handle invitations, and extending this to support "Crew-to-Crew" invites is the next logical step in development.


