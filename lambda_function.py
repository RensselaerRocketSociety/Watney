import boto3
from base64 import b64decode
from urlparse import parse_qs
import logging
import token
import secrets

ENCRYPTED_EXPECTED_TOKEN = secrets.token

kms = boto3.client('kms')
expected_token = kms.decrypt(CiphertextBlob = b64decode(ENCRYPTED_EXPECTED_TOKEN))['Plaintext']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

## TODO: Get priviliged users from DynamoDB
priviliged_users = ['briankelley', 'johnbehnke']
post_channel = '#general'

def post(user, command_text):
    '''
    Given a message, post that to #general and email it to the email list if 
    the user running the command has those priviliges

    Returns an error message if not successful, otherwise None
    '''
    if user not in priviliged_users:
        logger.warn('Unpriviliged user %s attempted to make announcement %s to the members' % 
                (user, command_text))
        return 'You are not a priviliged user. This attempt has been logged.'
        ## TODO: log this attempt to DynamoDB, potentially use SNS to notify officers?

    ## TODO: Post message in channel, email to mailing list.
    return ('User %s has posted the following message: \'%s\'. '
            'It has been posted in general and emailed to the mailing list.') % (user, command_text)

def lambda_handler(event, context):
    ## Mapping of commands to functions. Functions should take a username and command text
    commands = {
        '/post': post
    }

    req_body = event['body']
    logger.info('request body = %s' % req_body)
    params = parse_qs(req_body)
    token = params['token'][0]
    if token != expected_token:
        logger.error('Request token (%s) does not match exptected', token)
        raise Exception('Invalid request token')

    user = params['user_name'][0]
    command = params['command'][0]
    command_text = params['text'][0]

    return commands[command](user, command_text)
