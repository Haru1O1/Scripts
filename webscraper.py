"""
author: Jason Yeung
"""

import subprocess
import sys
import requests
import csv
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

urlDict = {}
maxDepth = 1

def exOrInLnk(evrLnk, pageLnk):
	filename = f"Links_Found.csv"
	with open(filename, 'w', newline = "") as csvfile:
		fieldnames = ["URL", "TYPE", "DEPTH"]

		csvWriter = csv.DictWriter(csvfile, fieldnames = fieldnames)
		csvWriter.writeheader()

		inLinks = 0
		exLinks = 0

		evrLnk = sorted(evrLnk.items(), key=lambda x: x[1])
		for link, curDepth in evrLnk:
			# is it internal
			if (link.startswith(pageLnk) or link.startswith('/') or link.startswith('#')):
				csvWriter.writerow({"URL": link, "TYPE": "INTERNAL", "DEPTH": curDepth})
				inLinks += 1
			else:
				csvWriter.writerow({"URL": link, "TYPE": "EXTERNAL", "DEPTH": curDepth})
				exLinks += 1
		csvWriter = csv.writer(csvfile)
		csvWriter.writerow(["Total Internal Links", f"{inLinks}"])
		csvWriter.writerow(["Total External Links", f"{exLinks}"])
	print(f"From the page {pageLnk} found {inLinks} Internal Link(s) and {exLinks} External Link(s)")
	print(f"The results have been saved in the {filename}")

def scrape(website, depth):
	if depth > maxDepth:
		pass
	else:
		try:
			response = requests.get(website, timeout=5)

			if response.status_code == 200:
				bSoup = BeautifulSoup(response.text, "html.parser")
				for lnks in bSoup.find_all('a', href = True):
					href = lnks['href']
					full_url = urljoin(website, href)
					if full_url not in urlDict:
						urlDict[full_url] = depth
						#print(full_url)
						scrape(full_url, depth+1)
		except:
			pass
def main():
	if len(sys.argv) < 2: # check if the input includes a argument
		print("Input should include a link.\n")
	else:
		URL = sys.argv[1]
		if not URL.startswith("https://"): # requests require the link to start with https...
			URL = "https://" + URL # add on https... in front if it does not include it already
		scrape(URL, 0)
		response = requests.get(URL)
		pageURL = response.url
		exOrInLnk(urlDict, pageURL)
		
if __name__ == "__main__":
    main()