import requests

# Specify the path to your text file containing the list of targets
file_path = './censys_results.txt'

output_file_path = './results.txt'  # Specify the desired output file path

# ANSI escape codes for colors
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
END_COLOR = '\033[0m'

try:
    with open(file_path, 'r') as file:
        targets = file.read().splitlines()

    with open(output_file_path, 'w') as output_file:
        for target in targets:
            try:
                response = requests.get(target)
                if response.status_code == 200:
                    result = f"{GREEN}{target} is responding with a 200 OK status.{END_COLOR}\n"
                    output_file.write(target + "\n")
                elif response.status_code >= 400:
                    result = f"{RED}{target} is responding with a {response.status_code} status.{END_COLOR}\n"
                elif response.status_code >= 300:
                    result = f"{YELLOW}{target} is responding with a {response.status_code} status (warning).{END_COLOR}\n"
                    output_file.write(target + "\n")
                print(result, end='')  # Print to terminal as well
            except requests.RequestException as e:
                result = f"{RED}Error accessing {target}: {e}{END_COLOR}\n"
                print(result, end='')  # Print to terminal as well

except FileNotFoundError:
    print(f"{RED}File not found: {file_path}{END_COLOR}")
except Exception as e:
    print(f"{RED}An error occurred: {e}{END_COLOR}")
