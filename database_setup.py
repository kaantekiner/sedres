import os
import configparser
import sqlite3

config_parser = configparser.ConfigParser()
config_parser.read('config.txt')
os.remove(config_parser['general_configuration']['database_file'])
db = sqlite3.connect(config_parser['general_configuration']['database_file'])
db_cursor = db.cursor()
db_cursor.execute("CREATE TABLE IF NOT EXISTS dns_queries (id INTEGER PRIMARY KEY, date TEXT, is_secure TEXT, dns TEXT)")
db_cursor.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, date TEXT, addr TEXT, alert_data TEXT)")





