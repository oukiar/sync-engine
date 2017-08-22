from flask import Flask, request, jsonify, make_response, g
from flask.ext.restful import reqparse
from werkzeug.exceptions import default_exceptions, HTTPException
from sqlalchemy.orm.exc import NoResultFound

from inbox.api.kellogs import APIEncoder
from nylas.logging import get_logger
from inbox.models import Namespace, Account
from inbox.models.session import global_session_scope
from inbox.api.validation import (bounded_str, ValidatableArgument,
                                  strict_parse_args, limit)
from inbox.api.validation import valid_public_id

from ns_api import app as ns_api
from ns_api import DEFAULT_LIMIT

from inbox.webhooks.gpush_notifications import app as webhooks_api

app = Flask(__name__)
# Handle both /endpoint and /endpoint/ without redirecting.
# Note that we need to set this *before* registering the blueprint.
app.url_map.strict_slashes = False

webhooks_list = []

known_servers = {
    'gmail.com':
        {
            'imap':{'server':'imap.gmail.com', 'port':993},
            'smtp':{'server':'smtp.gmail.com', 'port':465}
        }
}

def default_json_error(ex):
    """ Exception -> flask JSON responder """
    logger = get_logger()
    logger.error('Uncaught error thrown by Flask/Werkzeug', exc_info=ex)
    response = jsonify(message=str(ex), type='api_error')
    response.status_code = (ex.code
                            if isinstance(ex, HTTPException)
                            else 500)
    return response

# Patch all error handlers in werkzeug
for code in default_exceptions.iterkeys():
    app.error_handler_spec[None][code] = default_json_error


@app.before_request
def auth():
    """ Check for account ID on all non-root URLS """
    if request.path in ('/accounts', '/accounts/', '/', '/addaccount') \
            or request.path.startswith('/w/'):
        return

    if not request.authorization or not request.authorization.username:

        AUTH_ERROR_MSG = ("Could not verify access credential.", 401,
                          {'WWW-Authenticate': 'Basic realm="API '
                              'Access Token Required"'})

        auth_header = request.headers.get('Authorization', None)

        if not auth_header:
            return make_response(AUTH_ERROR_MSG)

        parts = auth_header.split()

        if (len(parts) != 2 or parts[0].lower() != 'bearer' or not parts[1]):
            return make_response(AUTH_ERROR_MSG)
        namespace_public_id = parts[1]

    else:
        namespace_public_id = request.authorization.username

    with global_session_scope() as db_session:
        try:
            valid_public_id(namespace_public_id)
            namespace = db_session.query(Namespace) \
                .filter(Namespace.public_id == namespace_public_id).one()
            g.namespace_id = namespace.id
            g.account_id = namespace.account.id
        except NoResultFound:
            return make_response((
                "Could not verify access credential.", 401,
                {'WWW-Authenticate': 'Basic realm="API '
                 'Access Token Required"'}))


@app.after_request
def finish(response):
    origin = request.headers.get('origin')
    if origin:  # means it's just a regular request
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = \
            'Authorization,Content-Type'
        response.headers['Access-Control-Allow-Methods'] = \
            'GET,PUT,POST,DELETE,OPTIONS,PATCH'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


@app.route('/accounts/')
def ns_all():
    """ Return all namespaces """
    # We do this outside the blueprint to support the case of an empty
    # public_id.  However, this means the before_request isn't run, so we need
    # to make our own session
    with global_session_scope() as db_session:
        parser = reqparse.RequestParser(argument_class=ValidatableArgument)
        parser.add_argument('limit', default=DEFAULT_LIMIT, type=limit,
                            location='args')
        parser.add_argument('offset', default=0, type=int, location='args')
        parser.add_argument('email_address', type=bounded_str, location='args')
        args = strict_parse_args(parser, request.args)

        query = db_session.query(Namespace)
        if args['email_address']:
            query = query.join(Account)
            query = query.filter_by(email_address=args['email_address'])

        query = query.limit(args['limit'])
        if args['offset']:
            query = query.offset(args['offset'])

        namespaces = query.all()
        encoder = APIEncoder()
        return encoder.jsonify(namespaces)


@app.route('/logout')
def logout():
    """ Utility function used to force browsers to reset cached HTTP Basic Auth
        credentials """
    return make_response((
        "<meta http-equiv='refresh' content='0; url=/''>.",
        401,
        {'WWW-Authenticate': 'Basic realm="API Access Token Required"'}))

#addaccount dependencies, from inbox-auth python script
from inbox.util.url import provider_from_address
from inbox.auth.base import handler_from_provider
from inbox.models import Account
from inbox.basicauth import NotSupportedError

@app.route('/addaccount', methods=['GET'])
def addaccount():
    email = request.args.get('email')
    email_address = email
    password = request.args.get('password')
    imapdata = None
    smtpdata = None
    status=None
    account = None
    authcode = None
    
    #try to solve the email servers data based by domain
    if '@' in email:
        emailuser, domain = email.split('@')
        
        if domain in known_servers:
            imapdata = known_servers[domain]['imap']
            smtpdata = known_servers[domain]['smtp']
            
        #if we have the imap data we must try to verify the account
        with global_session_scope() as db_session:
            account = db_session.query(Account).filter_by(
                email_address=email_address).first()
                
            if account is not None:
                print('Already have this account!')
                status = 'Already have this account!'
            else:
                auth_info = {}

                provider = provider_from_address(email_address)

                # Resolve unknown providers into either custom IMAP or EAS.
                if provider == 'unknown':
                    status = 'Waiting imap and smtp data'
                else:
                    auth_info['provider'] = provider
                    auth_handler = handler_from_provider(provider)
                    
                    #auth_info.update(auth_handler.interactive_auth(email_address))
                    
                    #auth code is returnet with providers like gmail
                    authcode = auth_handler.get_auth_url(email_address)
                    print('authcode: ', type(authcode) )
    
    encoder = APIEncoder()
    return encoder.jsonify({'email':email, 
                            'password':password, 
                            'status':status, 
                            'imap':imapdata, 
                            'smtp':smtpdata, 
                            'authcode':authcode})
    
@app.route('/addaccountauth', methods=['GET'])
def addaccountauth():
    email = request.args.get('email')
    auth_code = request.args.get('auth_code')
    status=None
 
    #if we have the imap data we must try to verify the account
    with global_session_scope() as db_session:
        account = db_session.query(Account).filter_by(
            email_address=email).first()
            
        if account is not None:
            print('Already have this account!')
            status = 'Already have this account!'
        else:
            auth_info = {}

            provider = provider_from_address(email)

            # Resolve unknown providers into either custom IMAP or EAS.
            if provider == 'unknown':
                status = 'Waiting imap and smtp data'
            else:
                auth_info['provider'] = provider
                auth_handler = handler_from_provider(provider)
                
                auth_handler.auth_step(auth_code)
                
                auth_info.update(auth_handler.auth_step(auth_code) )
                
                if False:
                    account = auth_handler.update_account(account, auth_info)
                else:
                    print('antes create account')
                    account = auth_handler.create_account(email, auth_info)
                    print('despues create account')

                try:
                    print('antes connect')
                    if auth_handler.connect_account(account):
                        print('despues connect')
                        db_session.add(account)
                        db_session.commit()
                        status = 'Saved account'
                    else:
                        print('Connection refused to: ' + email)
                        status = 'Connection refused to: ' + email
                except NotSupportedError as e:
                    print(str(e))
                '''
    
    encoder = APIEncoder()
    return encoder.jsonify({'email':email, 
                            'password':password, 
                            'status':status, 
                            'imap':imapdata, 
                            'smtp':smtpdata, 
                            'authcode':authcode})
    
@app.route('/webhooks')
def webhooks():
    encoder = APIEncoder()
    return encoder.jsonify(webhooks_list)
    
    
@app.route('/webhook/newmessage/<url>')
def webhook_newmessage(url):
    print("Webhook: " + url)
    webhooks_list.append(url)
    encoder = APIEncoder()
    return encoder.jsonify(webhooks_list)

app.register_blueprint(ns_api)
app.register_blueprint(webhooks_api)  # /w/...
