from flask import Flask, render_template_string
import threading

app = Flask(__name__)

html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Text Display GUI</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code&display=swap');

        body {
            margin: 0;
            height: 100vh;
            background-color: #111;
            color: white;
            font-family: 'Fira Code', 'Consolas', 'Courier New', monospace;
            overflow: hidden;
            position: relative;
        }
        #input-ui, #display-ui {
            text-align: center;
        }
        #display {
            font-size: 64px;
            user-select: none;
            position: absolute;
            bottom: 100px;      /* slightly above bottom */
            left: 35%;          /* slightly left of center */
            transform: translateX(-50%);
            font-family: 'Fira Code', 'Consolas', 'Courier New', monospace;
            white-space: pre;  /* preserves spacing */
        }
        #counter {
            position: absolute;
            top: 10px;
            left: 10px;
            font-size: 24px;
        }
        input, textarea, button {
            font-size: 20px;
            padding: 5px;
            margin: 5px;
            font-family: 'Fira Code', 'Consolas', 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div id="input-ui">
        <h2>Enter Settings</h2>
        <label>Characters per slide: </label>
        <input type="number" id="numInput" value="5"><br>
        <label>Text: </label><br>
        <textarea id="textInput" rows="10" cols="50"></textarea><br>
        <button id="startBtn">Start</button>
    </div>

    <div id="display-ui" style="display:none;">
        <div id="counter"></div>
        <div id="display"></div>
    </div>

    <script>
        let index = 0;
        let num = 0;
        let text = "";
        let lastSlashTime = 0;

        const inputUI = document.getElementById('input-ui');
        const displayUI = document.getElementById('display-ui');
        const display = document.getElementById('display');
        const counter = document.getElementById('counter');

        document.getElementById('startBtn').addEventListener('click', () => {
            num = parseInt(document.getElementById('numInput').value);
            text = document.getElementById('textInput').value.replace(/\\n/g, ""); // remove newlines
            index = 0;
            inputUI.style.display = 'none';
            displayUI.style.display = 'block';
            updateDisplay();
        });

        function updateDisplay() {
            if (index >= text.length) {
                display.innerText = "END";
                counter.innerText = "0 characters, 0 slides left";
            } else {
                display.innerText = text.substring(index, index + num);
                let charsLeft = text.length - index;
                let slidesLeft = Math.ceil(charsLeft / num);
                counter.innerText = charsLeft + " characters, " + slidesLeft + " slides left";
            }
        }

        document.addEventListener('keydown', function(event) {
            if (displayUI.style.display === 'block') {
                // Ctrl -> forward
                if (event.ctrlKey) {
                    index += num;
                    if (index > text.length) index = text.length;
                    updateDisplay();
                }
                // [ -> back
                else if (event.key === "[") {
                    index -= num;
                    if (index < 0) index = 0;
                    updateDisplay();
                }
                // / twice -> reset to input UI
                else if (event.key === "/") {
                    let now = new Date().getTime();
                    if (now - lastSlashTime < 400) { // double press within 400ms
                        displayUI.style.display = 'none';
                        inputUI.style.display = 'block';
                    }
                    lastSlashTime = now;
                }
            }
        });
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(html_template)

def run_flask():
    app.run(debug=False)

if __name__ == "__main__":
    threading.Thread(target=run_flask).start()
    print("Hosting on http://127.0.0.1:5000")
