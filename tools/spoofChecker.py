import asyncio
import re
import sys
import time
from datetime import date

import aiohttp
import pyfiglet
from bs4 import BeautifulSoup
from user_agent import generate_user_agent

start = time.time()

ua = generate_user_agent()
act = pyfiglet.figlet_format("Spoof_Checker")
print(act)


proxies={
        # "http": "http://gviljnrr-rotate:5ni0sn7ozmcl@p.webshare.io:80/",
        # "https": "http://gviljnrr-rotate:5ni0sn7ozmcl@p.webshare.io:80/" 
        # This proxies are dead
    }

async def whois(Domain):
    try:
        async with aiohttp.ClientSession() as session:
            url = "https://www.whois.com/whois/"
            headers = {"User-Agent": f"{ua}"}
            querystring = {"domain":Domain}
            response = await session.get(url, headers=headers, params=querystring, proxies=proxies, ssl=False)
            today = date.today()
            li = []
            res = await response.text
            soup = await BeautifulSoup(res, 'lxml')
            data = await soup.find_all('div', class_="df-value")
            for ta in data:
                p = ta.text
                pattern = re.compile("\d{4}")
                match = pattern.finditer(p)
                for matchs in match:
                    li.append(matchs.group(0))
            year = li[0]
            print(today.year - int(year))
    except Exception:
        return "0"


async def dmarc(Domain):
    try:
        async with aiohttp.ClientSession() as session:
            url = "https://easydmarc.com/tools/domain-scanner/content"
            querystring = {"domain":Domain}
            headers = {"User-Agent": f"{ua}"}
            response = await session.get(url, headers=headers,  params=querystring, proxies=proxies ,ssl=False)
            page = await response.text
            soup = await BeautifulSoup(page, 'lxml')
            number = await soup.find("div", class_="font-32 font-weight-bold").text
            print(number)
    except Exception:
        print("[!!!] ERROR WITH DMARC")
        sys.exit()


async def virustotal(Domain):
    try:
        async with aiohttp.ClientSession() as session:
            url = "https://www.virustotal.com/ui/search"
            querystring = {"limit":"20","relationships[comment]":"author,item","query":f"http://{Domain}"}
            headers = {
                    "User-Agent": f"{ua}",
                    "X-Tool": "vt-ui-main",
                    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
                    "X-VT-Anti-Abuse-Header": "MTY0ODQ2MTMzOTAtWkc5dWRDQmlaU0JsZG1scy0xNjYxNDcxOTM1Ljg1Ng==",
            }
            response = await session.get(url, headers=headers, params=querystring, proxies=proxies, ssl=False)
            result = await response.json()
            for data in result['data']:
                    print(data["attributes"]["last_analysis_stats"]["malicious"])
    except Exception:
        print("[!!!] ERROR WITH VIRUSTOTAL")
        sys.exit()


async def main():
    file = input("Enter Path For Domains : ")
    with open(file, 'r') as data:
        for domain in data:
            age = asyncio.create_task(whois(domain))
            misconfig = asyncio.create_task(dmarc(domain))
            malicious = asyncio.create_task(virustotal(domain))
            print(await age,await malicious,await misconfig)
            if str(await age) >= '10' and str(await misconfig) <= '1' and str(await malicious) == '0':
                with open('spoof_domain.txt', 'a') as domains:
                    domains.write(domain + '\n')
                print(f'[-] Can be vulnerable to spoofing : {domain}')
            else:
                print(f"[!] Not vulnerable Spoofing : {domain}")

asyncio.run(main())

end = time.time()
total_time = end - start
print(f"It took {total_time} seconds to make all the API calls")
print('You did it!')