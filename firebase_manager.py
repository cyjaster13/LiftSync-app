# firebase_manager.py
import firebase_admin
from firebase_admin import credentials, firestore, auth
import hashlib
import datetime
import re

# --- INITIALIZATION ---
# Ensure you have 'serviceAccountKey.json' in the same folder
try:
    cred = credentials.Certificate("serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("✓ Firebase initialized successfully")
except Exception as e:
    print(f"✗ Firebase initialization error: {e}")
    db = None

def init_db():
    """
    Firebase is schema-less, so we don't need to create tables.
    We just check if the admin exists and create if needed.
    """
    if db is None:
        print("Database not initialized!")
        return
        
    try:
        admin_ref = db.collection("users").document("admin")
        if not admin_ref.get().exists:
            admin_pw = hashlib.sha256("admin123".encode()).hexdigest()
            admin_ref.set({
                "username": "admin",
                "password": admin_pw,
                "is_admin": 1,
                "first_name": "Admin",
                "last_name": "User",
                "profile_pic": None,
                "created_at": firestore.SERVER_TIMESTAMP
            })
            print("✓ Admin user created in Firebase")
        else:
            print("✓ Admin user already exists")
    except Exception as e:
        print(f"✗ Error initializing database: {e}")

# --- USER FUNCTIONS ---

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, password, first_name, last_name, email=None):
    """
    Adds a new user with Firebase Authentication and Firestore profile.
    Now supports optional email for Firebase Auth.
    """
    try:
        # Use username as the Document ID to ensure uniqueness
        doc_ref = db.collection("users").document(username)
        
        if doc_ref.get().exists:
            return False, "Username already taken"

        # Create Firebase Auth user if email provided
        firebase_uid = None
        if email and is_valid_email(email):
            try:
                user_record = auth.create_user(
                    email=email,
                    password=password,
                    display_name=f"{first_name} {last_name}"
                )
                firebase_uid = user_record.uid
                print(f"✓ Firebase Auth user created: {email}")
            except Exception as auth_error:
                print(f"⚠ Firebase Auth creation failed: {auth_error}")
                # Continue with Firestore-only registration
        
        # Store user profile in Firestore
        hashed_pw = hash_password(password)
        doc_ref.set({
            "username": username,
            "password": hashed_pw,  # Keep hashed password as backup
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "firebase_uid": firebase_uid,
            "is_admin": 0,
            "profile_pic": None,
            "created_at": firestore.SERVER_TIMESTAMP,
            "last_login": None
        })
        
        print(f"✓ User profile created in Firestore: {username}")
        return True, "User created successfully"
        
    except Exception as e:
        print(f"✗ Error adding user: {e}")
        return False, f"Error: {str(e)}"

def is_valid_email(email):
    """Validates email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def verify_user(username, password):
    """
    Verifies user credentials and updates last login time.
    Supports both Firebase Auth and fallback password verification.
    """
    try:
        doc_ref = db.collection("users").document(username)
        doc = doc_ref.get()
        
        if not doc.exists:
            return False, False
        
        user_data = doc.to_dict()
        
        # Try Firebase Auth first if email exists
        if user_data.get("email"):
            try:
                # Note: Firebase Admin SDK doesn't directly verify password
                # In production, use Firebase Client SDK on frontend
                # For now, fall back to password hash verification
                pass
            except Exception as e:
                print(f"Firebase Auth verification error: {e}")
        
        # Verify password hash
        if user_data.get("password") == hash_password(password):
            # Update last login timestamp
            doc_ref.update({
                "last_login": firestore.SERVER_TIMESTAMP
            })
            print(f"✓ User logged in: {username}")
            return True, user_data.get("is_admin", 0)
        
        return False, False
        
    except Exception as e:
        print(f"✗ Error verifying user: {e}")
        return False, False

def get_user_profile_pic(username):
    doc = db.collection("users").document(username).get()
    if doc.exists:
        return doc.to_dict().get("profile_pic")
    return None

def get_user_first_name(username):
    doc = db.collection("users").document(username).get()
    if doc.exists:
        return doc.to_dict().get("first_name")
    return None

def get_user_last_name(username):
    doc = db.collection("users").document(username).get()
    if doc.exists:
        return doc.to_dict().get("last_name")
    return None

def update_user_credentials(old_username, new_username, new_password, profile_pic_path=None, first_name=None, last_name=None):
    """
    Updates user credentials.
    Note: Changing the Document ID (username) in Firestore requires 
    creating a new doc and deleting the old one.
    """
    old_doc_ref = db.collection("users").document(old_username)
    
    if not old_doc_ref.get().exists:
        return False, "User not found."

    # 1. Check if username is changing
    if old_username != new_username:
        new_doc_ref = db.collection("users").document(new_username)
        if new_doc_ref.get().exists:
            return False, "Username already taken."
        
        # We must copy data to new ID and delete old
        data = old_doc_ref.get().to_dict()
        data["username"] = new_username
        
        # Apply updates
        if new_password:
            data["password"] = hash_password(new_password)
        if profile_pic_path:
            data["profile_pic"] = profile_pic_path
        if first_name:
            data["first_name"] = first_name
        if last_name:
            data["last_name"] = last_name
            
        # Save new, delete old
        new_doc_ref.set(data)
        old_doc_ref.delete()
        
        # Update username in all workouts (Query and Batch Update)
        workouts = db.collection("workouts").where("username", "==", old_username).stream()
        for w in workouts:
            w.reference.update({"username": new_username})

    else:
        # Just update fields on existing doc
        updates = {}
        if new_password:
            updates["password"] = hash_password(new_password)
        if profile_pic_path:
            updates["profile_pic"] = profile_pic_path
        if first_name:
            updates["first_name"] = first_name
        if last_name:
            updates["last_name"] = last_name
            
        if updates:
            old_doc_ref.update(updates)

    return True, "Success"

# --- WORKOUT FUNCTIONS ---

def save_workout(username, workout_type, reps, good, bad, speed, status, video_path, metrics_log=None):
    """
    Saves workout session data to Firestore with enhanced metrics tracking.
    Returns the document ID for later reference.
    """
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        workout_data = {
            "username": username,
            "workout_type": workout_type,
            "timestamp": timestamp,
            "reps": reps,
            "good_form": good,
            "bad_form": bad,
            "avg_speed": speed,
            "status": status,
            "video_path": video_path,
            "ai_feedback": "",
            "created_at": firestore.SERVER_TIMESTAMP
        }
        
        # Add detailed metrics if provided
        if metrics_log:
            workout_data["metrics"] = metrics_log
        
        # Add returns a tuple: (update_time, document_reference)
        update_time, doc_ref = db.collection("workouts").add(workout_data)
        
        print(f"✓ Workout saved to Firestore: {doc_ref.id}")
        return doc_ref.id
        
    except Exception as e:
        print(f"✗ Error saving workout: {e}")
        return None

def get_user_history(username):
    """
    Retrieves workout history for a specific user from Firestore.
    Returns list of workout sessions with all details.
    """
    try:
        # Query workouts for specific user
        docs = db.collection("workouts")\
                 .where("username", "==", username)\
                 .order_by("timestamp", direction=firestore.Query.DESCENDING)\
                 .stream()
        
        history = []
        for doc in docs:
            r = doc.to_dict()
            history.append({
                "Workout Type": r.get("workout_type"),
                "Start Time": r.get("timestamp"),
                "Status": r.get("status"),
                "Reps Total": r.get("reps"),
                "Correct Form Count": r.get("good_form"),
                "Incorrect Form Count": r.get("bad_form"),
                "Video Path": r.get("video_path") if r.get("video_path") else "No Video",
                "AI Feedback": r.get("ai_feedback", "")
            })
        
        print(f"✓ Retrieved {len(history)} workouts for {username}")
        return history
        
    except Exception as e:
        print(f"✗ Error getting history: {e}")
        return []

def get_all_users():
    docs = db.collection("users").stream()
    users = []
    for doc in docs:
        d = doc.to_dict()
        # Return tuple format to match SQL expected output: (username, password, is_admin)
        users.append((d["username"], d["password"], d["is_admin"]))
    return users

def delete_user(username):
    """
    Deletes a user and all associated data from Firebase.
    Includes Firestore profile, workouts, and Firebase Auth account if exists.
    """
    try:
        # Get user data first
        user_doc = db.collection("users").document(username).get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            
            # Delete Firebase Auth account if exists
            if user_data.get("firebase_uid"):
                try:
                    auth.delete_user(user_data["firebase_uid"])
                    print(f"✓ Deleted Firebase Auth account for {username}")
                except Exception as e:
                    print(f"⚠ Could not delete Auth account: {e}")
        
        # Delete user document
        db.collection("users").document(username).delete()
        print(f"✓ Deleted user profile: {username}")
        
        # Delete associated workouts
        workouts = db.collection("workouts").where("username", "==", username).stream()
        count = 0
        for w in workouts:
            w.reference.delete()
            count += 1
        
        print(f"✓ Deleted {count} workout(s) for {username}")
        return True
        
    except Exception as e:
        print(f"✗ Error deleting user: {e}")
        return False

def update_workout_feedback(workout_id, feedback):
    """
    Updates the 'ai_feedback' field for a specific workout document.
    """
    try:
        # Check if workout_id is valid
        if not workout_id:
            print("Error: No workout ID provided for feedback update.")
            return False

        db.collection("workouts").document(workout_id).update({
            "ai_feedback": feedback
        })
        print(f"Feedback updated for workout {workout_id}")
        return True
    except Exception as e:
        print(f"Error updating feedback: {e}")
        return False