import streamlit as st
import pandas as pd
import plotly.express as px
import firebase_manager as db

# --- CONFIGURATION ---
st.set_page_config(page_title="Workout AI Dashboard", layout="wide", page_icon="💪")

# Initialize Firebase
db.init_db()

# --- SESSION STATE MANAGEMENT ---
if 'user' not in st.session_state:
    st.session_state.user = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = 0

# --- HELPER FUNCTIONS ---

def login_user(username, password):
    success, admin_status = db.verify_user(username, password)
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
                success, msg = db.add_user(new_user, new_pass, fname, lname, email)
                if success:
                    st.success("Account created! Please log in.")
                else:
                    st.error(msg)

def dashboard_page():
    st.title(f"Dashboard: {st.session_state.user}")
    
    # Fetch Data
    history = db.get_user_history(st.session_state.user)
    
    if not history:
        st.info("No workout data found yet.")
        return

    df = pd.DataFrame(history)
    
    # --- TOP METRICS ROW ---
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Workouts", len(df))
    with col2:
        st.metric("Total Reps", df['Reps Total'].sum())
    with col3:
        avg_good = df['Correct Form Count'].mean()
        st.metric("Avg Good Form", f"{avg_good:.1f}")
    with col4:
        total_forms = df['Correct Form Count'].sum() + df['Incorrect Form Count'].sum()
        accuracy = (df['Correct Form Count'].sum() / total_forms * 100) if total_forms > 0 else 0
        st.metric("Overall Accuracy", f"{accuracy:.1f}%")

    st.markdown("---")

    # --- ANALYTICS VISUALIZATION ---
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("📉 Progress Over Time")
        df['Start Time'] = pd.to_datetime(df['Start Time'])
        fig_line = px.line(df, x='Start Time', y='Reps Total', color='Workout Type', markers=True, 
                           title="Reps per Session")
        st.plotly_chart(fig_line, use_container_width=True)
        
    with c2:
        st.subheader("🎯 Form Consistency")
        form_df = df[['Start Time', 'Correct Form Count', 'Incorrect Form Count']].copy()
        form_df = form_df.melt('Start Time', var_name='Form Type', value_name='Count')
        
        fig_bar = px.bar(form_df, x='Start Time', y='Count', color='Form Type', 
                         title="Good vs Bad Form Comparison", barmode='group',
                         color_discrete_map={'Correct Form Count': 'green', 'Incorrect Form Count': 'red'})
        st.plotly_chart(fig_bar, use_container_width=True)

def history_page():
    st.title("📜 Workout History")
    history = db.get_user_history(st.session_state.user)
    
    if history:
        df = pd.DataFrame(history)
        
        # Remove Video Path column if it exists
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
    all_users = db.get_all_users()
    
    admin_df = pd.DataFrame(all_users, columns=["Username", "Hashed Password", "Is Admin"])
    st.dataframe(admin_df)
    
    st.subheader("Delete User")
    user_to_delete = st.selectbox("Select User to Delete", admin_df['Username'])
    
    if st.button("DELETE USER (Irreversible)"):
        if user_to_delete == "admin":
            st.error("Cannot delete the main admin account.")
        else:
            if db.delete_user(user_to_delete):
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
            # Removed "Log Workout" from the list
            menu = st.radio("Navigation", ["Dashboard", "History", "Admin" if st.session_state.is_admin else None])
            
            st.markdown("---")
            if st.button("Logout"):
                logout()

        if menu == "Dashboard":
            dashboard_page()
        elif menu == "History":
            history_page()
        elif menu == "Admin":
            admin_page()

if __name__ == "__main__":
    main()