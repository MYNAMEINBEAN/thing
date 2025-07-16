import json
import hashlib
import os
import uuid
import random
import threading
import time

from flask import Flask, request, jsonify, send_from_directory, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

USER_DATA_FILE = 'users.json'

# --- Server-side Session Management ---
# Stores active sessions: {session_token: {username: "user", sid: "socket_id"}}
# Note: sid is stored here for direct lookup in game logic, but can be None if user is not in a game
active_sessions = {}

# --- Multiplayer Game State ---
# Dictionary to store active games:
# {game_id: {players: {sid_x: username_x, sid_o: username_o}, board: [], turn: 'X', winner: None, draw: False, player_x_sid: sid_x, player_o_sid: sid_o}}
active_games = {}
# Queue for players waiting for a match: {username: sid}
waiting_players = {}
# Map SIDs to usernames for easier lookup (still useful for disconnects)
sid_to_username = {}
# Set to track all currently connected SIDs
connected_sids = set()

# --- Utility Functions ---

def load_users():
    """Loads user data from the JSON file.
    Handles older formats by converting string password hashes to dicts.
    Ensures all users have a 'coins' field.
    """
    users = {}
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as f:
            try:
                loaded_data = json.load(f)
                for username, user_data in loaded_data.items():
                    if isinstance(user_data, str):
                        users[username] = {
                            "password_hash": user_data,
                            "coins": 0
                        }
                    elif isinstance(user_data, dict):
                        if "coins" not in user_data:
                            user_data["coins"] = 0
                        users[username] = user_data
                    else:
                        print(f"Warning: Unexpected data type for user '{username}': {type(user_data)}")
            except json.JSONDecodeError:
                print(f"Error: {USER_DATA_FILE} is empty or corrupted. Starting with empty user data.")
                return {}
    return users

def save_users(users):
    """Saves user data to the JSON file."""
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    """Hashes a password using SHA256 for secure storage."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token():
    """Generates a unique session token."""
    return str(uuid.uuid4())

def check_win(board):
    """Checks if there's a winner on the given board."""
    winning_conditions = [
        [0, 1, 2], [3, 4, 5], [6, 7, 8], # Rows
        [0, 3, 6], [1, 4, 7], [2, 5, 8], # Columns
        [0, 4, 8], [2, 4, 6]             # Diagonals
    ]
    for condition in winning_conditions:
        a, b, c = condition
        if board[a] == board[b] and board[b] == board[c] and board[a] != '':
            return board[a] # Return 'X' or 'O'
    return None # No winner

def update_online_counts():
    """Emits the current online user count and Tic-Tac-Toe queue count."""
    total_online = len(connected_sids)
    tic_tac_toe_queue = len(waiting_players)
    socketio.emit('online_users_count', {'total': total_online}, namespace='/')
    socketio.emit('tic_tac_toe_online_players', {'count': tic_tac_toe_queue}, namespace='/')
    print(f"Online: {total_online}, Tic-Tac-Toe Queue: {tic_tac_toe_queue}")

# --- Flask Routes ---

@app.route('/signup', methods=['POST'])
def signup_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password cannot be empty."}), 400

    users = load_users()
    if username in users:
        return jsonify({"message": "Username already exists. Please choose a different one."}), 409
    else:
        users[username] = {"password_hash": hash_password(password), "coins": 0}
        save_users(users)
        
        # Generate session token and store
        session_token = generate_session_token()
        active_sessions[session_token] = {"username": username, "sid": None} # SID will be set on SocketIO connect
        
        return jsonify({"message": f"User '{username}' registered successfully!", "token": session_token, "username": username, "coins": 0}), 201

@app.route('/login', methods=['POST'])
def login_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password cannot be empty."}), 400

    users = load_users()
    user_data = users.get(username)
    if user_data and isinstance(user_data, dict) and user_data.get("password_hash") == hash_password(password):
        # Generate session token and store
        session_token = generate_session_token()
        active_sessions[session_token] = {"username": username, "sid": None} # SID will be set on SocketIO connect
        
        return jsonify({"message": f"Welcome, {username}! You have successfully logged in.", "token": session_token, "username": username, "coins": user_data.get("coins", 0)}), 200
    else:
        return jsonify({"message": "Invalid username or password."}), 401

@app.route('/guest_login', methods=['POST'])
def guest_login_api():
    """Handles guest login, creating a new guest account if necessary."""
    users = load_users()
    
    # Generate a unique guest username
    guest_number = 1
    while f"guest{guest_number}" in users:
        guest_number += 1
    guest_username = f"guest{guest_number}"
    guest_password = "guestpass" # Default password for guests

    # Create guest account if it doesn't exist
    if guest_username not in users:
        users[guest_username] = {"password_hash": hash_password(guest_password), "coins": 0}
        save_users(users)
        print(f"Created new guest account: {guest_username}")
    
    # Generate session token for the guest
    session_token = generate_session_token()
    active_sessions[session_token] = {"username": guest_username, "sid": None}
    
    return jsonify({"message": f"Welcome, {guest_username}! You are playing as a guest.", "token": session_token, "username": guest_username, "coins": users[guest_username].get("coins", 0)}), 200


@app.route('/check_session', methods=['GET'])
def check_session_api():
    """API endpoint to validate a session token and return user data."""
    token = request.args.get('token')
    if not token:
        return jsonify({"message": "Session token is missing."}), 400

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({"message": "Invalid or expired session token."}), 401

    username = session_data['username']
    users = load_users()
    user_data = users.get(username)

    if not user_data or not isinstance(user_data, dict):
        return jsonify({"message": "User data not found for session."}), 404

    return jsonify({"username": username, "coins": user_data.get("coins", 0)}), 200

@app.route('/logout', methods=['POST'])
def logout_api():
    """API endpoint to invalidate a session token."""
    token = request.get_json().get('token')
    if token in active_sessions:
        del active_sessions[token]
        print(f"Session {token} logged out.")
        return jsonify({"message": "Logged out successfully."}), 200
    return jsonify({"message": "Invalid session token."}), 400


@app.route('/update_coins', methods=['POST'])
def update_coins_api():
    data = request.get_json()
    token = data.get('token') # Now expects a token
    coins_to_add = data.get('coins')

    if not token or coins_to_add is None or not isinstance(coins_to_add, (int, float)):
        return jsonify({"message": "Invalid request data."}), 400

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({"message": "Invalid or expired session token."}), 401
    
    username = session_data['username']

    users = load_users()
    if username not in users:
        return jsonify({"message": "User not found."}), 404
    user_data = users[username]
    if not isinstance(user_data, dict):
        print(f"Error: User data for '{username}' is not a dictionary. Cannot update coins.")
        return jsonify({"message": "User data format error."}), 500
    current_coins = user_data.get("coins", 0)
    user_data["coins"] = current_coins + coins_to_add
    save_users(users)

    return jsonify({"message": f"Coins updated for {username}. New total: {user_data['coins']}", "new_coins": user_data["coins"]}), 200

@app.route('/get_user_coins', methods=['GET'])
def get_user_coins_api():
    """API endpoint to get a user's current coin count."""
    token = request.args.get('token') # Now expects a token
    if not token:
        return jsonify({"message": "Session token is missing."}), 400

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({"message": "Invalid or expired session token."}), 401
    
    username = session_data['username']

    users = load_users()
    user_data = users.get(username)

    if not user_data or not isinstance(user_data, dict):
        return jsonify({"message": "User not found or data format error."}), 404

    return jsonify({"username": username, "coins": user_data.get("coins", 0)}), 200


# --- Flask Routes to serve HTML files ---
@app.route('/play')
def play_page():
    return send_from_directory('.', 'play.html')

@app.route('/play.html')
def play_html_page():
    return send_from_directory('.', 'play.html')

@app.route('/')
def index_page():
    return send_from_directory('.', 'index.html')

@app.route('/index.html')
def index_html_page():
    return send_from_directory('.', 'index.html')

@app.route('/tick-tack-toe/ai.html')
def tic_tac_toe_ai_game():
    return send_from_directory('tick-tack-toe', 'ai.html')

@app.route('/tick-tack-toe/multiplayer.html')
def tic_tac_toe_multiplayer_game():
    return send_from_directory('tick-tack-toe', 'multiplayer.html')

# --- SocketIO Event Handlers ---

@socketio.on('connect')
def handle_connect():
    connected_sids.add(request.sid)
    print(f"Client connected: {request.sid}. Total online: {len(connected_sids)}")
    update_online_counts()

@socketio.on('disconnect')
def handle_disconnect():
    connected_sids.discard(request.sid)
    print(f"Client disconnected: {request.sid}. Total online: {len(connected_sids)}")
    
    # Find the session associated with this SID
    disconnected_username = None
    for token, session_data in list(active_sessions.items()):
        if session_data.get('sid') == request.sid:
            disconnected_username = session_data['username']
            # IMPORTANT CHANGE: Do NOT delete the token here. Just clear the SID.
            session_data['sid'] = None 
            print(f"Cleared SID for session {token} (user: {disconnected_username}) on disconnect. Session token remains active.")
            break

    # Remove from waiting queue if present (using disconnected_username for robustness)
    if disconnected_username and disconnected_username in waiting_players and waiting_players[disconnected_username] == request.sid:
        del waiting_players[disconnected_username]
        print(f"Removed {disconnected_username} from waiting queue.")

    # Check if player was in an active game and end it
    for game_id, game_state in list(active_games.items()):
        if request.sid in game_state['players']:
            opponent_sid = None
            for sid, player_username in game_state['players'].items():
                if sid != request.sid:
                    opponent_sid = sid
                    break

            if opponent_sid:
                emit('opponent_disconnected', {'message': f"{disconnected_username or 'An opponent'} has disconnected. Game ended."}, room=opponent_sid)
                leave_room(game_id, sid=opponent_sid)
            del active_games[game_id]
            print(f"Game {game_id} ended due to player disconnect: {disconnected_username}")
            break
    update_online_counts()


@socketio.on('register_user_sid')
def register_user_sid(data):
    token = data.get('token')
    username_from_client = data.get('username') # For logging/cross-check

    if not token:
        print(f"Error: register_user_sid received no token from SID {request.sid}")
        return

    session_data = active_sessions.get(token)
    if not session_data:
        print(f"Error: register_user_sid received invalid token {token} from SID {request.sid}")
        emit('session_invalid', {'message': 'Your session is invalid or expired. Please log in again.'}, room=request.sid)
        return

    # Critical update: If this token was previously associated with a different SID,
    # clean up the old SID's mapping before assigning the new one.
    old_sid_for_token = session_data.get('sid')
    if old_sid_for_token and old_sid_for_token != request.sid:
        print(f"User {session_data['username']} (token: {token}) reconnected with new SID {request.sid}. Old SID was {old_sid_for_token}.")
        # Remove old SID from sid_to_username and connected_sids
        if old_sid_for_token in sid_to_username:
            del sid_to_username[old_sid_for_token]
        connected_sids.discard(old_sid_for_token)
        # Also, if the old SID was in the waiting queue, remove it
        if session_data['username'] in waiting_players and waiting_players[session_data['username']] == old_sid_for_token:
            del waiting_players[session_data['username']]
            print(f"Removed old SID {old_sid_for_token} for {session_data['username']} from waiting queue.")

    session_data['sid'] = request.sid
    sid_to_username[request.sid] = session_data['username']

    print(f"Registered SID {request.sid} for user {session_data['username']} with token {token}")
    
    # Emit an acknowledgement back to the client
    emit('ack_sid_registered', {'message': 'SID registered successfully'}, room=request.sid)

    # Reconnection logic for active games
    for game_id, game_state in active_games.items():
        if session_data['username'] in game_state['players'].values():
            # Find the player's current SID in the game state
            player_char_in_game = None
            current_sid_in_game = None
            for s_id, u_name in game_state['players'].items():
                if u_name == session_data['username']:
                    current_sid_in_game = s_id
                    player_char_in_game = ('X' if game_state['player_x_sid'] == s_id else 'O')
                    break
            
            if current_sid_in_game and current_sid_in_game != request.sid:
                # User reconnected with a new SID, update game state
                game_state['players'][request.sid] = session_data['username']
                del game_state['players'][current_sid_in_game] # Remove old SID from game players

                if game_state['player_x_sid'] == current_sid_in_game:
                    game_state['player_x_sid'] = request.sid
                elif game_state['player_o_sid'] == current_sid_in_game:
                    game_state['player_o_sid'] = request.sid
                
                join_room(game_id, sid=request.sid)
                leave_room(game_id, sid=current_sid_in_game) # Make old SID leave room
                print(f"User {session_data['username']} reconnected to game {game_id} with new SID {request.sid} (old was {current_sid_in_game})")
                emit('game_state', {'board': game_state['board'], 'turn': game_state['turn']}, room=request.sid)
                break # User can only be in one game
        
    update_online_counts()


@socketio.on('join_multiplayer_game')
def handle_join_multiplayer_game(data):
    token = data.get('token')
    if not token:
        emit('error', {'message': 'Authentication token missing.'}, room=request.sid)
        return

    session_data = active_sessions.get(token)
    # Validate token AND ensure the SID in active_sessions matches the current request.sid
    # This check is crucial for preventing actions from stale SIDs.
    if not session_data or session_data.get('sid') != request.sid:
        emit('error', {'message': 'Invalid or expired session token, or SID mismatch. Please re-login.'}, room=request.sid)
        return
    
    username = session_data['username']

    # Ensure the user is not already waiting or in a game
    if username in waiting_players or any(username in game['players'].values() for game in active_games.values()):
        emit('matchmaking_status', {'message': 'You are already in queue or in a game.'}, room=request.sid)
        return

    # Find an opponent
    opponent_username = None
    opponent_sid = None
    # Iterate over a copy of waiting_players to allow modification during iteration
    for uname, osid in list(waiting_players.items()):
        # Ensure opponent is not the same user (e.g., if reconnected quickly)
        # and that the opponent's SID is distinct from the current player's SID
        if osid != request.sid and uname != username: # Compare usernames too
            opponent_username = uname
            opponent_sid = osid
            del waiting_players[opponent_username] # Remove opponent from queue
            break

    if opponent_username and opponent_sid:
        game_id = str(uuid.uuid4())
        
        # Randomly assign X and O
        players_sids = [request.sid, opponent_sid]
        random.shuffle(players_sids)
        player_x_sid = players_sids[0]
        player_o_sid = players_sids[1]

        active_games[game_id] = {
            'players': {
                player_x_sid: sid_to_username[player_x_sid],
                player_o_sid: sid_to_username[player_o_sid]
            },
            'board': ['', '', '', '', '', '', '', '', ''],
            'turn': 'X',
            'winner': None,
            'draw': False,
            'player_x_sid': player_x_sid,
            'player_o_sid': player_o_sid
        }

        join_room(game_id, sid=request.sid)
        join_room(game_id, sid=opponent_sid)

        emit('match_found', {'game_id': game_id, 'player_char': 'X', 'opponent_username': sid_to_username[player_o_sid]}, room=player_x_sid)
        emit('match_found', {'game_id': game_id, 'player_char': 'O', 'opponent_username': sid_to_username[player_x_sid]}, room=player_o_sid)
        
        print(f"Match found! Game {game_id} between {sid_to_username[player_x_sid]} (X) and {sid_to_username[player_o_sid]} (O)")
    else:
        # Only add to waiting_players if the user is not already there with the current SID
        # This prevents duplicate entries if client sends multiple join requests
        if username not in waiting_players or waiting_players[username] != request.sid:
            waiting_players[username] = request.sid
            emit('matchmaking_status', {'message': 'Waiting for an opponent...'}, room=request.sid)
            print(f"{username} added to waiting queue.")
        else:
            emit('matchmaking_status', {'message': 'Already in queue.'}, room=request.sid)
            print(f"{username} is already in waiting queue with this SID.")
    update_online_counts()

@socketio.on('make_move')
def handle_make_move(data):
    token = data.get('token') # Expect token for authentication
    game_id = data.get('game_id')
    index = data.get('index')
    player_char = data.get('player_char')

    if not token:
        emit('error', {'message': 'Authentication token missing.'}, room=request.sid)
        return

    session_data = active_sessions.get(token)
    if not session_data or session_data.get('sid') != request.sid:
        emit('error', {'message': 'Invalid or expired session token, or SID mismatch. Please re-login.'}, room=request.sid)
        return
    
    current_username = session_data['username']

    if game_id not in active_games:
        emit('error', {'message': 'Game not found.'}, room=request.sid)
        return

    game = active_games[game_id]

    # Validate player's turn and character based on the username associated with the current SID
    if player_char == 'X' and game['players'].get(game['player_x_sid']) != current_username:
        emit('error', {'message': 'Unauthorized move: Not player X.'}, room=request.sid)
        return
    elif player_char == 'O' and game['players'].get(game['player_o_sid']) != current_username:
        emit('error', {'message': 'Unauthorized move: Not player O.'}, room=request.sid)
        return

    if game['turn'] != player_char:
        emit('error', {'message': "It's not your turn."}, room=request.sid)
        return

    if not (0 <= index <= 8) or game['board'][index] != '':
        emit('error', {'message': 'Invalid move: cell already taken or out of bounds.'}, room=request.sid)
        return

    # Apply the move
    game['board'][index] = player_char

    winner_char = check_win(game['board'])
    if winner_char:
        game['winner'] = winner_char
        emit('game_over', {'winner': winner_char, 'board': game['board']}, room=game_id)
        print(f"Game {game_id} over. Winner: {winner_char}")

        # Award coins to the winner
        winner_username = None
        if winner_char == 'X':
            winner_username = sid_to_username.get(game['player_x_sid'])
        else:
            winner_username = sid_to_username.get(game['player_o_sid'])

        if winner_username:
            users = load_users()
            if winner_username in users and isinstance(users[winner_username], dict):
                users[winner_username]["coins"] = users[winner_username].get("coins", 0) + 10
                save_users(users)
                # Emit to both players in the game room
                emit('coins_updated', {'username': winner_username, 'new_coins': users[winner_username]["coins"]}, room=game['player_x_sid'])
                emit('coins_updated', {'username': winner_username, 'new_coins': users[winner_username]["coins"]}, room=game['player_o_sid'])
                print(f"Awarded 10 coins to {winner_username}. New total: {users[winner_username]['coins']}")
            else:
                print(f"Warning: Could not find user {winner_username} to award coins.")

        # Clean up game
        leave_room(game_id, sid=game['player_x_sid'])
        leave_room(game_id, sid=game['player_o_sid'])
        del active_games[game_id]
        update_online_counts()
    elif '' not in game['board']:
        game['draw'] = True
        emit('game_over', {'winner': 'draw', 'board': game['board']}, room=game_id)
        print(f"Game {game_id} over. Draw.")
        # Clean up game
        leave_room(game_id, sid=game['player_x_sid'])
        leave_room(game_id, sid=game['player_o_sid'])
        del active_games[game_id]
        update_online_counts()
    else:
        # Change turn
        game['turn'] = 'O' if player_char == 'X' else 'X'
        # Broadcast updated board and turn
        emit('game_state', {'board': game['board'], 'turn': game['turn']}, room=game_id)
        print(f"Game {game_id} - Move by {player_char} at {index}. Next turn: {game['turn']}")

@socketio.on('leave_multiplayer_game')
def handle_leave_multiplayer_game(data):
    token = data.get('token')
    game_id = data.get('game_id')
    
    if not token:
        print(f"Error: leave_multiplayer_game received no token from SID {request.sid}")
        return

    session_data = active_sessions.get(token)
    if not session_data or session_data.get('sid') != request.sid:
        print(f"Error: leave_multiplayer_game received invalid token {token} or SID mismatch from SID {request.sid}")
        return
    
    username = session_data['username']

    if game_id in active_games:
        game = active_games[game_id]
        
        # Find opponent SID
        opponent_sid = None
        for sid, uname in game['players'].items():
            if uname == username and sid == request.sid: # Ensure it's the correct player leaving
                pass
            else:
                opponent_sid = sid

        if opponent_sid:
            emit('opponent_left', {'message': f"{username} has left the game."}, room=opponent_sid)
            leave_room(game_id, sid=opponent_sid)

        leave_room(game_id, sid=request.sid)
        del active_games[game_id]
        print(f"Game {game_id} ended by {username} leaving.")
    elif username in waiting_players and waiting_players[username] == request.sid:
        del waiting_players[username]
        print(f"{username} left the matchmaking queue.")
    update_online_counts()

# --- Background task to periodically update online counts ---
def background_online_count_emitter():
    while True:
        socketio.sleep(5)
        update_online_counts()

if __name__ == '__main__':
    threading.Thread(target=background_online_count_emitter, daemon=True).start()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
