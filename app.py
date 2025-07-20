from flask import Flask, render_template, request
import hashlib
import requests

app = Flask(__name__)

def check_pwned_api(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1pass[:5], sha1pass[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return count
    return 0

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']
        count = check_pwned_api(password)
        if count:
            result = f'This password has been seen {count} times! Consider changing it.'
        else:
            result = 'This password was NOT found in any data breach.'
        return render_template('index.html', result=result, password=password)
    return render_template('index.html', result=None)

if __name__ == '__main__':
    app.run(debug=True)
