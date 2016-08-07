import boto3

from base64 import b64decode
from urlparse import parse_qs
import logging
import token
import re
import json

import secrets

ENCRYPTED_EXPECTED_TOKENS = secrets.token

kms = boto3.client('kms')
expected_tokens = [kms.decrypt(CiphertextBlob = b64decode(item))['Plaintext'] for item in ENCRYPTED_EXPECTED_TOKENS]

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('RRS_Privileged_Users')
privileged_users = [str(user['username']) for user in table.scan()['Items']]

post_channels = ['morebottesting', 'bottesting']

## Usernames must start with a letter or number, but then can contain periods, dashes, 
## and underscores. All lowercase.
username_regex = r'^[a-z0-9][a-z0-9._-]*$'


def post(user, command_text, channel):
    '''
    Given a message, post that to #general and email it to the email list if 
    the user running the command has those priviliges

    Returns an error message if not successful, otherwise a success message
    '''
    if user not in privileged_users:
        # logger.warn('Unprivileged user %s attempted to make announcement %s to the members' % 
        #         (user, command_text))
        return '{"channel" : "%s", "text" : "You are not a privileged user. This attempt has been logged."}' %channel
        ## TODO: log this attempt to DynamoDB, potentially use SNS to notify officers?

    ## TODO: Post message in channel, email to mailing list.
    return ('{"response_type": "in_channel", "channel" : "%s",  "text" : "User %s has posted the following message : \'%s\'. '
            'It has been posted in general and emailed to the mailing list."}') % (channel, user, command_text)


def add_privileged_user(user, command_text):
    '''
    Given a user, add him or her to the privileged user list if the requester is privileged

    Returns an error message if not successful, otherwise a success message
    '''
    if user not in privileged_users:
        logger.warn('Unprivileged user %s ran /adduser on %s' % 
                (user, command_text))
        return 'You are not a privileged user. This attempt has been logged.'
        ## TODO: log this attempt to DynamoDB, potentially use SNS to notify officers?

    cleaned_name = command_text.strip()
    if cleaned_name[0] == '@':
        if len(cleaned_name) == 1:
            return 'You need to give me an actual username'
        cleaned_name = cleaned_name[1:]

    if re.match(username_regex, cleaned_name):
        ## It's a valid username
        logger.info('User %s adding user %s to the privileged user group' % 
            (user, cleaned_name))
        
        if cleaned_name in privileged_users:
            return '%s already in the privileged user group.' % cleaned_name

        table.put_item(Item = {
            'username': cleaned_name
        })

        return 'Successfully added user %s to the privileged user group' % cleaned_name
    else:
        logger.warn('User %s attempted to add invalid user %s to the privileged user group' %
            (user, cleaned_name))
        return 'Invalid username %s. If this looks like an error, contact a programmer.' % cleaned_name


def remove_privileged_user(user, command_text):
    '''
    Given a user, remove him or her from the privileged user list if the requester is privileged

    Returns an error message if not successful, otherwise a success message
    '''
    if user not in privileged_users:
        logger.warn('Unprivileged user %s ran /removeuser on %s' % 
                (user, command_text))
        return 'You are not a privileged user. This attempt has been logged.'
        ## TODO: log this attempt to DynamoDB, potentially use SNS to notify officers?

    cleaned_name = command_text.strip()
    if cleaned_name[0] == '@':
        if len(cleaned_name) == 1:
            return 'You need to give me an actual username'
        cleaned_name = cleaned_name[1:]

    if re.match(username_regex, cleaned_name):
        ## It's a valid username
        logger.info('User %s removing user %s from the privileged user group' % 
            (user, cleaned_name))

        if cleaned_name not in privileged_users:
            return '%s not in the privileged user group.' % cleaned_name
        
        table.delete_item(Key = {
            'username': cleaned_name
        })
        
        return 'Successfully removed user %s from the privileged user group' % cleaned_name
    else:
        logger.warn('User %s attempted to remove invalid user %s from the privileged user group' %
            (user, cleaned_name))
        return 'Invalid username %s. If this looks like an error, contact a programmer.' % cleaned_name


def lambda_handler(event, context):
    ## Mapping of commands to functions. Functions should take a username and command text
    commands = {
        '/post': post,
        '/adduser': add_privileged_user,
        '/removeuser': remove_privileged_user
    }

    logger.info(event)
    req_body = event['body']
    #logger.info('request body = %s' % req_body)
    params = parse_qs(req_body)
    token = params['token'][0]
    if token not in expected_tokens:
        logger.error('Request token (%s) does not match expected', token)
        raise Exception('Invalid request token')


    user = params['user_name'][0]
    command = params['command'][0]
    channel = params['channel_name'][0]
    command_text = params['text'][0]

    return json.loads('%s'%commands[command](user, command_text, post_channels[0]))
