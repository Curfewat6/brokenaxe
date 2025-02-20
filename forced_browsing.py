def forced_browsing(session, url):
    """ False-positive prone test for forced browsing
        since it is reliant on status codes. """
    r = session.get(url, timeout=10, verify=False)
    if r.status_code == 200:
        print(f"\nForced browsing to admin-protected portal: {url}")

    elif r.status_code == 404:
        print(f"\nPage ({url}) does not exist")
    else:
        print(f"\nAccess control appears to be working: {url}")

    return r.status_code