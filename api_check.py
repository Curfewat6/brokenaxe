import requests

def challenge_api(session, api_endpoints):
    for test in api_endpoints:    
        try:
            response = session.get(test, timeout=10, verify=False)
            print(f"[+] Testing API: {test}     (Status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")

def test_api_endpoints(session, api_links, found_queries):
    api_links_to_test = []
    for api in api_links:
        for query in found_queries:
            full_api_url = f"{api}/?{query}"
            try:
                response = session.get(full_api_url, timeout=10, verify=False)
                print(f"[+] Testing API: {full_api_url}     (Status: {response.status_code})")
                if response.status_code == 200:
                    api_links_to_test.append(full_api_url)
                    print(f"    [!] Potential API query: {query}")
            except requests.exceptions.RequestException as e:
                print(f"    [!] Error: {e}")
    return api_links_to_test