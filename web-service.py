import flask
from flask import render_template, request
import configparser
import socket
import sqlite3
app = flask.Flask(__name__)


@app.route('/')
def index_page():
    return render_template('index.html',
                           hostname=socket.gethostname(),
                           web_access_address=web_access_address,
                           web_access_port=web_access_port,
                           dns_service_address=dns_service_address,
                           dns_service_port=dns_service_port,
                           dns_resolve_address=dns_resolve_address)


@app.route('/logs')
def logs_page():
    return render_template('logs.html')


@app.route('/getlogs')
def get_logs():
    global log_file
    try:
        with open(log_file) as f:
            content = f.readlines()
        content.reverse()
        response = ""
        for i in range(60):
            response += str(content[i]) + "<br>"
        return response
    except Exception as err:
        print("Error occurred:", str(err))
        exit(0)


@app.route('/get_resolve_counts')
def get_resolve_counts():
    global config_parser
    db = sqlite3.connect(config_parser['general_configuration']['database_file'])
    db_cursor = db.cursor()
    db_cursor.execute("SELECT * FROM dns_queries WHERE is_secure = 'True'")
    secure_que_count = str(len(db_cursor.fetchall()))
    db_cursor.execute("SELECT * FROM dns_queries WHERE is_secure = 'False'")
    insecure_que_count = str(len(db_cursor.fetchall()))
    total_que_count = str(int(insecure_que_count) + int(secure_que_count))
    return total_que_count + "," + secure_que_count + "," + insecure_que_count


@app.route('/get_alert_count')
def get_alert_count():
    global config_parser
    db = sqlite3.connect(config_parser['general_configuration']['database_file'])
    db_cursor = db.cursor()
    db_cursor.execute("SELECT * FROM alerts")
    que_count = str(len(db_cursor.fetchall()))
    return que_count


@app.route('/get_alerts')
def get_alerts():
    global config_parser
    db = sqlite3.connect(config_parser['general_configuration']['database_file'])
    db_cursor = db.cursor()
    db_cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 43")
    response = ""
    for alert in db_cursor.fetchall():
        response += str(alert)[:-1][1:] + "<br>"
    return response




config_parser = configparser.ConfigParser()
config_parser.read('config.txt')
web_access_address = config_parser['general_configuration']['web_access_address']
web_access_port = config_parser['general_configuration']['web_access_port']
dns_service_address = config_parser['general_configuration']['dns_service_address']
dns_service_port = config_parser['general_configuration']['dns_service_port']
dns_resolve_address = config_parser['general_configuration']['dns_resolve_address']
log_file = config_parser['general_configuration']['log_file']


if __name__ == '__main__':
    app.run(debug=True, port=web_access_port, host=web_access_address)
