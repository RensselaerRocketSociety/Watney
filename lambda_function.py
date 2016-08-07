import boto3

from base64 import b64decode
from urlparse import parse_qs
import logging
import token
import re
import json

import secrets

import requests

ENCRYPTED_EXPECTED_TOKENS = secrets.token

kms = boto3.client('kms')
expected_tokens = [kms.decrypt(CiphertextBlob = b64decode(item))['Plaintext'] for item in ENCRYPTED_EXPECTED_TOKENS]

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('RRS_Privileged_Users')

post_channel = '#morebottesting'
parse_level = 'full'
username = 'Watney'
icon_url = 'https://s3-us-west-2.amazonaws.com/slack-files2/avatars/2016-08-01/65268633191_44503e401be992822065_48.jpg'

## Usernames must start with a letter or number, but then can contain periods, dashes, 
## and underscores. All lowercase.
username_regex = r'^[a-z0-9][a-z0-9._-]*$'

post_message_url = 'https://slack.com/api/chat.postMessage'

def extractEmotes(input):

    #Super simple implementation of this. Can we use a nice regex instead of counting ":"'s? Yea.
    #Do I know how to do that off the top of my head w/o counting? No.
    #Only thing we need to do is strip out any punctuation that might be attached,
    #Like in this case: "This is a contrived example :kappa:!". In this algo, its gonna
    #pull out ":kappa:!" as the emote. But hey, I wrote this in a shorter time than it took me to write this comment.
    #Ultimately there is gonna have to be a function like "formatter" that takes in the raw slack input and
    #formats it into the multipart message or prepares it to do that. This can either be this function or another whole function 
    #That calls this. IDK mannhnnnnnnnnnn
    workingList = input.split(" ")
    emojiList = []
    for word in workingList:
        if word.count(":") == 2:
            emojiList.append(word)
    if len(emojiList) == 0:
        return None
    else:
        return emojiList
def privileged_users():
    return [str(user['username']) for user in users_table.scan()['Items']]

def construct_json(**kwargs):
    '''
    Given keyword arguments, construct a JSON string based on that.

    Example:
    
        construct_json(text='\'Hello\', "world"') 
    
    should return 

        {
            "text": "'Hello', \"world\""
        }
    '''
    return json.dumps(kwargs)

def post_to_channel(message):
    data = {
        'text': message, 
        'token': secrets.slack_auth_token,
        'channel': post_channel,
        'parse_level': parse_level,
        'username': username,
        'icon_url': icon_url
    }

    return requests.post(post_message_url, data=data)


def post(user, command_text):
    '''
    Given a message, post that to #general and email it to the email list if 
    the user running the command has those privileges

    Returns an error message if not successful, otherwise a success message
    '''
    if user not in privileged_users():
        logger.warn('Unprivileged user %s attempted to make announcement %s to the members' % 
                (user, command_text))
        return construct_json(text='You are not a privileged user. This attempt has been logged.')
        ## TODO: log this attempt to DynamoDB, potentially use SNS to notify officers?

    response = post_to_channel(command_text)

    if response.status_code != 200:
        return construct_json(text='Something went wrong posting the message! Got %d %d' 
            % (response.status_code, response.reason))

    return construct_json(text=('Successfully posted the following message: "%s". '
        'It has been posted in %s and emailed to the mailing list'
        % (command_text, post_channel)))


def add_privileged_user(user, command_text):
    '''
    Given a user, add him or her to the privileged user list if the requester is privileged

    Returns an error message if not successful, otherwise a success message
    '''
    if user not in privileged_users():
        logger.warn('Unprivileged user %s ran /adduser on %s' % 
                (user, command_text))
        return construct_json(text='You are not a privileged user. This attempt has been logged.')
        ## TODO: log this attempt to DynamoDB, potentially use SNS to notify officers?

    cleaned_name = command_text.strip()
    if cleaned_name[0] == '@':
        if len(cleaned_name) == 1:
            return construct_json(text='You need to give me an actual username')
        cleaned_name = cleaned_name[1:]

    if re.match(username_regex, cleaned_name):
        ## It's a valid username
        logger.info('User %s adding user %s to the privileged user group' % 
            (user, cleaned_name))
        
        if cleaned_name in privileged_users():
            return construct_json(text='%s already in the privileged user group.' % cleaned_name)

        users_table.put_item(Item = {
            'username': cleaned_name
        })

        return construct_json(text='Successfully added user %s to the privileged user group' 
            % cleaned_name)
    else:
        logger.warn('User %s attempted to add invalid user %s to the privileged user group' 
            % (user, cleaned_name))
        return construct_json(text=('Invalid username %s. If this looks like an error, '
            'contact a programmer.') % cleaned_name)


def remove_privileged_user(user, command_text):
    '''
    Given a user, remove him or her from the privileged user list if the requester is privileged

    Returns an error message if not successful, otherwise a success message
    '''
    if user not in privileged_users():
        logger.warn('Unprivileged user %s ran /removeuser on %s' % 
                (user, command_text))
        return construct_json(text='You are not a privileged user. This attempt has been logged.')
        ## TODO: log this attempt to DynamoDB, potentially use SNS to notify officers?

    cleaned_name = command_text.strip()
    if cleaned_name[0] == '@':
        if len(cleaned_name) == 1:
            return construct_json(text='You need to give me an actual username')
        cleaned_name = cleaned_name[1:]

    if re.match(username_regex, cleaned_name):
        ## It's a valid username
        logger.info('User %s removing user %s from the privileged user group' % 
            (user, cleaned_name))

        if cleaned_name not in privileged_users():
            return construct_json(text='%s not in the privileged user group.' % cleaned_name)
        
        users_table.delete_item(Key = {
            'username': cleaned_name
        })
        
        return construct_json(text='Successfully removed user %s from the privileged user group' 
            % cleaned_name)
    else:
        logger.warn('User %s attempted to remove invalid user %s from the privileged user group' %
            (user, cleaned_name))
        return construct_json(text=('Invalid username %s. If this looks like an error, '
            'contact a programmer.') % cleaned_name)


def lambda_handler(event, context):
    ## Mapping of commands to functions. Functions should take a username and command text
    commands = {
        '/post': post,
        '/adduser': add_privileged_user,
        '/removeuser': remove_privileged_user
    }

    logger.info(event)
    req_body = event['body']
    params = parse_qs(req_body)
    token = params['token'][0]

    if token not in expected_tokens:
        logger.error('Request token (%s) does not match expected', token)
        raise Exception('Invalid request token')

    user = params['user_name'][0]
    command = params['command'][0]
    command_text = params['text'][0]

    return json.loads(commands[command](user, command_text))
