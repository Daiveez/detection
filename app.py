from flask import Flask, request, render_template
import joblib
import pandas as pd

# Load the trained model and original categorical values
model = joblib.load('tommy_model.pkl')
original_browser = joblib.load('original_browser.pkl')

# Initialize Flask app
app = Flask(__name__)

# Rule-based function to assign threat level
def assign_threat_level(login_attempts, failed_logins, session_duration):
    if login_attempts <= 3 and failed_logins <= 1 and session_duration <= 300:
        return 'Low'
    elif login_attempts <= 5 and failed_logins <= 3 and session_duration <= 600:
        return 'Medium'
    else:
        return 'High'

# Home route to render the HTML form
@app.route('/')
def home():
    return render_template('index.html', original_browser=original_browser)

# Prediction route to handle form submission
@app.route('/predict', methods=['POST'])
def predict():
    # Get the input data from the form
    input_data = {
        'client_name': request.form['client_name'],
        'login_attempts': int(request.form['login_attempts']),
        'session_duration': float(request.form['session_duration']),
        'failed_logins': int(request.form['failed_logins']),
        'browser_type': request.form['browser_type'],
        'unusual_time_access': int(request.form['unusual_time_access'])
    }

    # Map categorical inputs to numerical values
    input_data['browser_type'] = original_browser.index(input_data['browser_type'])

    # Convert input data into a DataFrame
    input_df = pd.DataFrame([input_data])

    # Select the relevant features for prediction
    features = ['login_attempts', 'session_duration', 'failed_logins', 'browser_type', 'unusual_time_access']
    input_features = input_df[features]

    # Make a prediction
    prediction = model.predict(input_features)

    # Assign threat level
    threat_level = assign_threat_level(
        input_data['login_attempts'],
        input_data['failed_logins'],
        input_data['session_duration']
    )

    # Map prediction to a human-readable result
    result = "Attack Detected" if prediction[0] == 1 else "No Attack Detected"

    # Return the prediction result and threat level to the HTML template
    return render_template('index.html', prediction_text=result, client_name=input_data['client_name'], threat_level=threat_level)

# Run the Flask app on a different port
if __name__ == '__main__':
    app.run(debug=True, port=5001)