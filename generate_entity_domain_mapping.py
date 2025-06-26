import json
import os
import subprocess

REPO_URL = "https://github.com/duckduckgo/tracker-radar"

def generate_entities():
    if not os.path.exists("tracker-radar"):
        subprocess.run(["git", "clone", REPO_URL], check=True)
    
    directory = "tracker-radar/domains/US"

    data = {}
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            with open(filepath, 'r') as f:
                obj = json.load(f)
                company = filename.strip(".json")
                data[company] = obj

    with open("ddg.json", 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    generate_entities()

