import sys
import json
import requests
import app_auth
from random import choice
from requests.auth import HTTPBasicAuth
from pathlib import Path
import discogs_client
from discogs_client.exceptions import HTTPError

#Authorization process based off example from: https://github.com/jesseward/discogs-oauth-example

def authorizeDiscogs(client):

    # Give the client our consumer key/secret
    client.set_consumer_key(app_auth.consumer_key, app_auth.consumer_secret)
    token, secret, url = client.get_authorize_url()

    print(' == Request Token == ')
    print(f'    * oauth_token        = {token}')
    print(f'    * oauth_token_secret = {secret}')
    print()

    # Ask the user to authorize my app
    print(f'Please browse to the following URL {url}')
    accepted = 'n'
    while accepted.lower() == 'n':
        print
        accepted = input(f'Have you authorized me at {url} [y/n] :')

    # Waiting for user input. Here they must enter the verifier key that was
    # provided at the unqiue URL generated above.
    oauth_verifier = input('Verification code : ')

    try:
        access_token, access_secret = client.get_access_token(oauth_verifier)
    except HTTPError:
        print('Unable to authenticate.')
        sys.exit(1)

    # fetch the identity object for the current logged in user.
    user = client.identity()

    print
    print(' == User ==')
    print(f'    * username           = {user.username}')
    print(f'    * name               = {user.name}')
    print(' == Access Token ==')
    print(f'    * oauth_token        = {access_token}')
    print(f'    * oauth_token_secret = {access_secret}')
    print(' Authentication complete. Future requests will be signed with the above tokens.')

    f = open("shuffle_auth.txt", "w")
    f.write("{{\"oauth_token\":\"{}\",\"oauth_token_secret\":\"{}\",\"username\":\"{}\"}}".format(access_token, access_secret, user.username))

    f = open("shuffle_auth.txt", "r")
    print(f.read())

def checkForAuth():
    if Path("./shuffle_auth.txt").exists():
        f = open("shuffle_auth.txt", "r")
        json_string = f.read()
        obj = json.loads(json_string)
        if 'oauth_token' in obj and 'oauth_token_secret' in obj and 'username' in obj:
            return obj['oauth_token'], obj['oauth_token_secret'], obj['username']
    return False

def getAlbumListFrom(releaseList):
    albums = []
    for release in releaseList:
        album = ""
        if 'basic_information' in release:
            info = release['basic_information']
            if 'title' in info:
                album += info['title']
            if 'artists' in info:
                album += ' by ' + info['artists'][0]['name']
        if album not in albums:
            albums.append(album)
    return albums

def getUserAuthorization():
    #Request user to authorize until we have token and secret
    while checkForAuth() == False:
        authorizeDiscogs(client)

    #Assign our tokens and username
    authResults = checkForAuth()
    token = authResults[0]
    secret = authResults[1]
    username = authResults[2]

    return username, HTTPBasicAuth(token, secret)



# =====================   MAIN   ==========================
# Unique user agent
user_agent = 'discogs_shuffle_scrobble'

# Instantiate dicogs client object using our user agent
client = discogs_client.Client(user_agent)

username, auth = getUserAuthorization()

#Make initial request (first page if multiple pages in folder)
url = 'https://api.discogs.com/users/{}/collection/folders/0/releases'.format(username) #0 is the All folder
r = requests.get(url, auth=auth)
jsonResponse = r.json()

#Parse the first response
allAlbums = []
allAlbums.extend(getAlbumListFrom(jsonResponse['releases']))

#Make requests for additional pages while we have them, appending those results to allAlbums
while 'pagination' in jsonResponse and 'urls' in jsonResponse['pagination'] and 'next' in jsonResponse['pagination']['urls']:
    url = jsonResponse['pagination']['urls']['next']
    r = requests.get(url, auth)
    jsonResponse = r.json()
    allAlbums.extend(getAlbumListFrom(jsonResponse['releases']))

#Pick a random album and suggest it to the user
decision = choice(allAlbums)
print('You should listen to', decision)



