import streamlit as st
import pandas as pd
import plotly.express as px
import firebase_admin
from firebase_admin import credentials, firestore, auth
import hashlib
import datetime
import re

# --- CONFIGURATION ---
st.set_page_config(page_title="LiftSync Dashboard", layout="wide", page_icon="💪")

# --- FIREBASE INITIALIZATION ---
# This checks if it's running live on Streamlit Cloud (using secrets) or locally
@st.cache_resource
def init_firebase():
    try:
        if not firebase_admin._apps:
            if "firebase" in st.secrets:
                cert_dict = dict(st.secrets["firebase"])
                cred = credentials.Certificate(cert_dict)
                print("✓ Firebase initialized using Streamlit Secrets (Cloud)")
            else:
                cred = credentials.Certificate("serviceAccountKey.json")
                print("✓ Firebase initialized using local JSON file (Local)")
            
            firebase_admin.initialize_app(cred)
        
        return firestore.client()
    except Exception as e:
        st.error(f"Firebase initialization error: {e}")
        return None

db = init_firebase()

def ensure_admin_exists():
    if db is None: return
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
                "created_at": firestore.SERVER_TIMESTAMP
            })
    except Exception as e:
        print(f"Error creating admin: {e}")

ensure_admin_exists()

# --- DATABASE FUNCTIONS ---

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def add_user(username, password, first_name, last_name, email=None):
    try:
        doc_ref = db.collection("users").document(username)
        if doc_ref.get().exists:
            return False, "Username already taken"

        firebase_uid = None
        if email and is_valid_email(email):
            try:
                user_record = auth.create_user(email=email, password=password, display_name=f"{first_name} {last_name}")
                firebase_uid = user_record.uid
            except Exception as auth_error:
                print(f"Auth creation failed: {auth_error}")
        
        doc_ref.set({
            "username": username,
            "password": hash_password(password),
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "firebase_uid": firebase_uid,
            "is_admin": 0,
            "created_at": firestore.SERVER_TIMESTAMP
        })
        return True, "User created successfully"
    except Exception as e:
        return False, f"Error: {str(e)}"

def verify_user(username, password):
    try:
        doc = db.collection("users").document(username).get()
        if not doc.exists: return False, False
        
        user_data = doc.to_dict()
        if user_data.get("password") == hash_password(password):
            db.collection("users").document(username).update({"last_login": firestore.SERVER_TIMESTAMP})
            return True, user_data.get("is_admin", 0)
        return False, False
    except:
        return False, False

def get_user_history(username):
    try:
        docs = db.collection("workouts").where("username", "==", username).order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
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
                "Video Path": r.get("video_path")
            })
        return history
    except Exception as e:
        print(f"Error getting history: {e}")
        return []

def get_all_users():
    docs = db.collection("users").stream()
    return [(d.to_dict()["username"], d.to_dict()["password"], d.to_dict()["is_admin"]) for d in docs]

def delete_user(username):
    try:
        user_doc = db.collection("users").document(username).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            if user_data.get("firebase_uid"):
                try: auth.delete_user(user_data["firebase_uid"])
                except: pass
        db.collection("users").document(username).delete()
        
        workouts = db.collection("workouts").where("username", "==", username).stream()
        for w in workouts: w.reference.delete()
        return True
    except:
        return False

# --- SESSION STATE MANAGEMENT ---
if 'user' not in st.session_state:
    st.session_state.user = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = 0

# --- HELPER FUNCTIONS ---
def login_user(username, password):
    success, admin_status = verify_user(username, password)
    if success:
        st.session_state.user = username
        st.session_state.is_admin = admin_status
        st.success(f"Welcome back, {username}!")
        st.rerun()
    else:
        st.error("Invalid username or password")

def logout():
    st.session_state.user = None
    st.session_state.is_admin = 0
    st.rerun()

# --- PAGES ---

def login_page():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.title("LiftSync")
        st.subheader("Login")
        
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            login_user(username, password)
            
        st.markdown("---")
        with st.expander("Create New Account"):
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            fname = st.text_input("First Name")
            lname = st.text_input("Last Name")
            email = st.text_input("Email (Optional)")
            
            if st.button("Register"):
                success, msg = add_user(new_user, new_pass, fname, lname, email)
                if success:
                    st.success("Account created! Please log in.")
                else:
                    st.error(msg)

def dashboard_page():
    st.title(f"Dashboard: {st.session_state.user}")
    
    # Auto-refresh feature for live updates
    if st.button("🔄 Refresh Data"):
        st.rerun()
        
    history = get_user_history(st.session_state.user)
    
    if not history:
        st.info("No workout data found yet.")
        return

    df = pd.DataFrame(history)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("Total Workouts", len(df))
    with col2: st.metric("Total Reps", df['Reps Total'].sum())
    with col3: 
        avg_good = df['Correct Form Count'].mean()
        st.metric("Avg Good Form", f"{avg_good:.1f}")
    with col4:
        total_forms = df['Correct Form Count'].sum() + df['Incorrect Form Count'].sum()
        accuracy = (df['Correct Form Count'].sum() / total_forms * 100) if total_forms > 0 else 0
        st.metric("Overall Accuracy", f"{accuracy:.1f}%")

    st.markdown("---")
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("📉 Progress Over Time")
        df['Start Time'] = pd.to_datetime(df['Start Time'])
        fig_line = px.line(df, x='Start Time', y='Reps Total', color='Workout Type', markers=True, title="Reps per Session")
        st.plotly_chart(fig_line, use_container_width=True)
        
    with c2:
        st.subheader("🎯 Form Consistency")
        form_df = df[['Start Time', 'Correct Form Count', 'Incorrect Form Count']].copy()
        form_df = form_df.melt('Start Time', var_name='Form Type', value_name='Count')
        fig_bar = px.bar(form_df, x='Start Time', y='Count', color='Form Type', title="Good vs Bad Form Comparison", barmode='group', color_discrete_map={'Correct Form Count': 'green', 'Incorrect Form Count': 'red'})
        st.plotly_chart(fig_bar, use_container_width=True)

def history_page():
    st.title("📜 Workout History")
    history = get_user_history(st.session_state.user)
    
    if history:
        df = pd.DataFrame(history)
        if "Video Path" in df.columns:
            df = df.drop(columns=["Video Path"])
        st.dataframe(df, use_container_width=True)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download History as CSV", csv, "workout_history.csv", "text/csv")
    else:
        st.write("No history available.")

def admin_page():
    st.title("🔒 Admin Panel")
    if st.session_state.is_admin != 1:
        st.warning("Access Denied")
        return

    st.subheader("User Management")
    all_users = get_all_users()
    admin_df = pd.DataFrame(all_users, columns=["Username", "Hashed Password", "Is Admin"])
    st.dataframe(admin_df)
    
    st.subheader("Delete User")
    user_to_delete = st.selectbox("Select User to Delete", admin_df['Username'])
    
    if st.button("DELETE USER (Irreversible)"):
        if user_to_delete == "admin":
            st.error("Cannot delete the main admin account.")
        else:
            if delete_user(user_to_delete):
                st.success(f"User {user_to_delete} deleted.")
                st.rerun()

# --- MAIN APP LAYOUT ---

def main():
    if not st.session_state.user:
        login_page()
    else:
        with st.sidebar:
            st.image("https://cdn-icons-png.flaticon.com/512/2548/2548530.png", width=100)
            st.write(f"Logged in as: **{st.session_state.user}**")
            if st.session_state.is_admin == 1:
                st.write("*(Admin Access)*")
            
            st.markdown("---")
            menu = st.radio("Navigation", ["Dashboard", "History", "Admin" if st.session_state.is_admin else None])
            
            st.markdown("---")
            if st.button("Logout"):
                logout()

        if menu == "Dashboard": dashboard_page()
        elif menu == "History": history_page()
        elif menu == "Admin": admin_page()

if __name__ == "__main__":
    main()