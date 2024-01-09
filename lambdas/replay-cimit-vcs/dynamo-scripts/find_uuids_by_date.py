import argparse
import json
import os

argParser = argparse.ArgumentParser()
argParser.add_argument("-e", "--env", help="the name of the environment folder to target e.g. build")
argParser.add_argument("-f", "--file", help="name of the file to query e.g. `address-results.json`")
argParser.add_argument("-d", "--date", help="date to query for in the exact format `YYYY-MM-DD` e.g `2024-01-04`")

args = argParser.parse_args()

env = args.env
file = args.file
date = args.date

results = []
dir = os.path.dirname(__file__)
read_file = os.path.join(dir, f"{env}/{file}.json")
write_file = os.path.join(dir, f"uuid_results/{env}-{file}.json")

print(f"Reading file {env}/{file} for day: {date}")
with open(read_file, "r") as results_file:
  file = json.load(results_file)
  for item in file["Items"]:
    date_created = item["dateCreated"]["S"][:-20]
    if date_created == date:
      results.append(item)

with open(write_file, "w") as results_file:
  json.dump(results, results_file)

print(f"Search found {len(results)} results")
print(f"Results written to {write_file}")