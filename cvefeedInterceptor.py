import requests
import json
import time
import tkinter as tk
from tkinter import ttk
import pandas as pd

class SCAPAutoNotifier:
    def __init__(self, api_url, cve_feed_url, api_key):
        self.api_url = api_url
        self.cve_feed_url = cve_feed_url
        self.api_key = api_key

    def authenticate(self):
        headers = {'Authorization': f'Bearer {self.api_key}'}
        response = requests.post(f'{self.api_url}/authenticate', headers=headers)

        if response.status_code == 200:
            print('Authentication successful!')
            return True
        else:
            print(f'Authentication failed. Status Code: {response.status_code}')
            return False

    def get_cve_feed(self):
        response = requests.get(self.cve_feed_url)

        if response.status_code == 200:
            cve_data = response.json()
            return cve_data
        else:
            print(f'Failed to retrieve CVE feed. Status Code: {response.status_code}')
            return None

    def notify_vulnerabilities(self, cve_data):
        # Add your notification logic here
        print('Received CVE Feed:')
        print(cve_data)
    
    def parse_cve_data(self,cve_data):
        #try:
        #    parsed_data = json.loads(cve_data)
        #    cve_entries = parsed_data.get('CVE_Items', [])
        #    return cve_entries
        return cve_data.get('vulnerabilities', [])


    def display_cve_table(self,cve_entries):
        root = tk.Tk()
        root.title("CVE Data Table")
        # Convert data to pandas DataFrame
        data = []
        for index, entry in enumerate(cve_entries):
            cve_id = entry.get('cve', {}).get('id', 'N/A')
            metrics_list = entry.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [])
            severity = metrics_list[0].get('cvssData', {}).get('baseSeverity', 'N/A') if metrics_list else 'N/A'
            #severity = entry.get('cve', {}).get('metrics', {}).get('cvssMetricV31', 'N/A').get('baseSeverity', 'N/A')
            descriptions = entry.get('cve', {}).get('descriptions', [])
            description = descriptions[0].get('value', 'N/A') if descriptions else 'N/A'
            data.append([index, cve_id, severity, description])

        columns = ["Index", "CVE ID", "Base Severity", "Description"]
        df = pd.DataFrame(data, columns=columns)

    # Create Treeview widget
        tree = ttk.Treeview(root, columns=columns, show='headings')
        for col in columns:
            tree.heading(col, text=col)
            #max_length = max(df[col].astype(str).apply(len).max(), len(col))
            tree.column(col, width=320, anchor='w')  # Adjust the multiplier as needed
        # Create vertical scrollbar
        y_scrollbar = ttk.Scrollbar(root, orient='vertical', command=tree.yview)
        y_scrollbar.pack(side='right', fill='y')
        tree.configure(yscrollcommand=y_scrollbar.set)
        # Create horizontal scrollbar
        x_scrollbar = ttk.Scrollbar(root, orient='horizontal', command=tree.xview)
        x_scrollbar.pack(side='bottom', fill='x')
        tree.configure(xscrollcommand=x_scrollbar.set)
        
        for index, entry in enumerate(cve_entries):
            cve_id = entry.get('cve', {}).get('id', 'N/A')
            severity = entry.get('cve', {}).get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'N/A')
            description = entry.get('cve', {}).get('descriptions', [{}])[0].get('value', 'N/A')

        # Insert a dummy value for the index, as it may not align properly with multiline text
            values = [index, cve_id, severity, description]
            tree.insert("", index, values=values)
        
        tree.pack(expand=True, fill=tk.BOTH)
        
    # Insert data into the Treeview
    #    for index, row in df.iterrows():
    #        tree.insert("", index, values=list(row))
        root.mainloop()    
# usage
api_url = ' http://127.0.0.1:5000'
cve_feed_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft&cveId=CVE-2010-0026'
api_key = 'your_api_key'
scap_notifier = SCAPAutoNotifier(api_url, cve_feed_url, api_key)

if scap_notifier.authenticate():
    while True:
        cve_data = scap_notifier.get_cve_feed()

        if cve_data:
            cve_entries = scap_notifier.parse_cve_data(cve_data)    
            scap_notifier.notify_vulnerabilities(cve_data)
            scap_notifier.display_cve_table(cve_entries)

        # Sleep for a specified interval (e.g., 24 hours)
        #time.sleep(7200)  # 24 hours in seconds
        
