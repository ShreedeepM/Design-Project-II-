from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)


#made this changes
# VULNERABILITY 1: Hardcoded Secret Key
# 'bandit' will flag this as a hardcoded password/key.
app.config['SECRET_KEY'] = 'supersecretkey123' 
#hi
# VULNERABILITY 2: SQL Injection (CWE-89)
# 'bandit' and 'CodeQL' will flag this.
# A user can provide malicious input like "' OR '1'='1" to bypass logic.
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    db = sqlite3.connect('example.db')
    cursor = db.cursor()
    
    # This is the vulnerable line
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}") 
    
    user = cursor.fetchone()
    db.close()
    return str(user)

# VULNERABILITY 3: Cross-Site Scripting (XSS) (CWE-79)
# 'CodeQL' will likely flag this. 'bandit' might too.
# The 'name' parameter is rendered directly to the HTML without escaping.
# A user can visit /hello?name=<script>alert(1)</script> to run arbitrary JavaScript.
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # Using render_template_string with unescaped input is dangerous
    return render_template_string(f'<h1>Hello, {name}!</h1>')

if __name__ == '__main__':
    # VULNERABILITY 4: Debug Mode Enabled (CWE-215)
    # 'bandit' will flag this immediately.
    # Running in debug mode in a production environment exposes
    # a live debugger and other sensitive information.
    app.run(debug=True, host='0.0.0.0') 
