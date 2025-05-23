
import streamlit as st
import pandas as pd
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.chrome.options import Options
import time
import json
import requests
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.core.os_manager import ChromeType

from selenium.common.exceptions import TimeoutException

@st.cache_resource
def get_driver():
    return webdriver.Chrome(
        service=Service(
            ChromeDriverManager(chrome_type=ChromeType.CHROMIUM).install()
        ),
        options=options,
    )
def fun(username,password):
    # ===== CONFIGURATION =====
    Cognito_URL = 'https://user.faceprep.online/'  # Replace with actual Cognito login URL
    USERNAME = username
    PASSWORD = password
    json_response = {}
    # ========================
    options=Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1920,1080")
    msg = st.empty()
    service = Service(ChromeDriverManager().install())
    
    # Setup Selenium WebDriver (using Chrome in GUI mode)
   driver = webdriver.Chrome(ChromeDriverManager(version="114.0.5735.90").install(), options=options)  # This will open the browser with a GUI window
    msg.info("Signing In.Please wait")
        # Open Cognito login page
    driver.get(Cognito_URL)

    wait=WebDriverWait(driver,20)
        # Find username and password fields using ID (since fields have id="username" and id="password")
    #username_field = driver.find_element(By.ID, 'username')  # Use By.ID to find the username field
    #password_field = driver.find_element(By.ID, 'password')  # Use By.ID to find the password field


    username_field = wait.until(EC.element_to_be_clickable((By.ID, 'username')))
    password_field = wait.until(EC.element_to_be_clickable((By.ID, 'password')))

        # Input username and password
    username_field.send_keys(USERNAME)
    password_field.send_keys(PASSWORD)
    msg.empty()
    msg.info("Logging In.This may take a while.")
    sign_in_button = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[span[text()='Sign in']]")))   
        # Find the "Sign in" button and click it using the text inside the button
    #sign_in_button = driver.find_element(By.XPATH, "//button[span[text()='Sign in']]")  # Locate the button by its text
    sign_in_button.click()  # Click the sign-in button
    target_div = wait.until(EC.visibility_of_element_located((
        By.CSS_SELECTOR,
        "div.ant-row.ant-row-space-between.ant-row-middle"
    )))
    
    #time.sleep(5)  # Wait for the challenge page to load
    m = driver.execute_script("return localStorage.getItem('idToken')")
    m=m.rpartition('.')[0]
    accessToken=m+".idToken"
    accessToken=driver.execute_script(f"return localStorage.getItem('{accessToken}')")
    #Name:"custom:idskUserId value
    userData=m+".userData"
    userId=driver.execute_script(f"return localStorage.getItem('{userData}')")
    userId=json.loads(userId)
    userId=userId['UserAttributes'][3]['Value']

    driver.quit()  # Close the browser window after the task is complete
    Uname=USERNAME
    Uname=Uname.replace("@", "%40")
    msg.empty()
    msg.info("Processing.Please wait for a movement")
   
     
    u=f'https://jzbjcywkl7.execute-api.ap-south-1.amazonaws.com/api/v1/d2s/assessmentsessions/clients/75a207e9-7a8e-4068-a6d0-e0327d04ee0d/candidates/{USERNAME}/assessmentSessions/dashboard/summary?from=0&size=30&candidateId={userId}&emailId={Uname}' 
    headers={'authorization': f'Bearer {accessToken}' }


    response = requests.get(u,headers=headers)

    if response.status_code == 200:
        r=json.loads(response.text)
        
        st.session_state.vb=int(float(r['records'][0]['score']))
        st.session_state.lct=int(float(r['records'][1]['score']))
        msg.empty()

    


# Simulated result data using globals
def process_results():
    vb = st.session_state.get("vb", 0)
    lct = st.session_state.get("lct", 0)

    data = [
        {"Course Name": "Verbal Ability", "Score out of 50": vb},
        {"Course Name": "Logical & Critical Thinking", "Score out of 50": lct},
    ]
    for entry in data:
        entry["Result"] = "Pass" if entry["Score out of 50"] >= 25 else "Fail"
    df = pd.DataFrame(data)
    df.index = df.index + 1
    styled_df = df.style.set_table_styles([
        {'selector': 'thead th', 'props': [('background-color', 'orange'), ('color', 'white')]}
    ])
    
    return styled_df

# Initialize session state variables
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "login_attempted" not in st.session_state:
    st.session_state.login_attempted = False

def handle_login():
    st.session_state.login_attempted = True
    try:
        fun(st.session_state.username_input, st.session_state.password_input)
        st.session_state.logged_in = True
        st.session_state.login_attempted = True
    except TimeoutException:
        st.error("Invalid username or password")
        st.session_state.login_attempted = False

    

# Login Page
def login_page():
   
    
    st.markdown("<h1 style='color: orange;'>FacePrep Results</h1>", unsafe_allow_html=True)

    username = st.text_input("Email", key="username_input")
    password = st.text_input("Password", type="password", key="password_input")

    st.button("Login", on_click=handle_login, disabled=st.session_state.login_attempted)
  
        
       

# Result Page
def result_page():
    
    st.markdown("<h1 style='color: orange;'>SEE Results</h1>", unsafe_allow_html=True)

    df = process_results()
    st.dataframe(df)
     
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.login_attempted = False
        st.rerun()

# Main App
if st.session_state.logged_in:
    result_page()
else:
    login_page()
