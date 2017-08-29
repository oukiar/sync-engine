from flask import Flask, request, jsonify, make_response, g
#from flask.ext.cache import Cache
from flask_cors import CORS
from flask.ext.restful import reqparse
from werkzeug.exceptions import default_exceptions, HTTPException
from sqlalchemy.orm.exc import NoResultFound

from inbox.api.kellogs import APIEncoder
from nylas.logging import get_logger
from inbox.models import Namespace, Account
from inbox.models.session import global_session_scope
from inbox.models.session import session_scope
from inbox.api.validation import (bounded_str, ValidatableArgument,
                                  strict_parse_args, limit)
from inbox.api.validation import valid_public_id

from ns_api import app as ns_api
from ns_api import DEFAULT_LIMIT

from inbox.webhooks.gpush_notifications import app as webhooks_api

app = Flask(__name__)
#CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

#cache = Cache(app,config={'CACHE_TYPE': 'simple'})

#app.config['CACHE_TYPE'] = 'simple'
#cache.init_app(app)

# Handle both /endpoint and /endpoint/ without redirecting.
# Note that we need to set this *before* registering the blueprint.
app.url_map.strict_slashes = False

webhooks_list = []

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
    print request.path
    print request.path[:6]
    if request.path in ('/accounts', '/accounts/', '/', '/addaccount', '/addaccountauth', '/deleteaccount', '/getauth', '/downloads') \
            or request.path.startswith('/w/'):
        return

    if request.path[:6] == '/files':
        return

    #print request.authorization

    if not request.authorization or not request.authorization.username:

        AUTH_ERROR_MSG = ("Could not verify access credential.", 401,
                          {'WWW-Authenticate': 'Basic realm="API '
                              'Access Token Required"'})

        auth_header = request.headers.get('Authorization', None)
        
        #print(auth_header)

        if not auth_header:
            return make_response(AUTH_ERROR_MSG)

        parts = auth_header.split()



        #if (len(parts) != 2 or parts[0].lower() != 'bearer' or not parts[1]):
        #    print('23456789')
        #    return make_response(AUTH_ERROR_MSG)
        namespace_public_id = parts[0]

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
    password = request.args.get('password')
    imap_server = request.args.get('imap_server')
    imap_port = request.args.get('imap_port')
    smtp_server = request.args.get('smtp_server')
    smtp_port = request.args.get('smtp_port')
    status=None
    account = None
    authcode = None
    namespace = None
    account_id = None
    
    with session_scope(0)  as db_session:
        account = db_session.query(Account).filter_by(
            email_address=email).first()
            
        if account is not None:
            print('Already have this account!')
            status = 'Already have this account!'
        else:
            auth_info = {}

            provider = provider_from_address(email)
            
            print('Provider', provider)
            
            if provider in ('gmail'):
                
                auth_info['provider'] = provider
                auth_handler = handler_from_provider(provider)
                
                #auth code is returnet with providers like gmail
                authcode = auth_handler.get_auth_url(email)
                print('authcode: ', type(authcode) )
                
                status = 'Waiting auth_code'

            # Resolve unknown providers into either custom IMAP or EAS.
            elif provider == 'unknown':
                print(imap_server)
                if imap_server == "" or imap_port == "" or smtp_server == "" or smtp_port == "":
                    status = 'Waiting imap and smtp data'
                else:
                    status = 'Imap account connected'
                    
                    auth_info['provider'] = "custom"
                    auth_handler = handler_from_provider(auth_info['provider'])
                    
                    auth_info.update(
                                imap_server_host=imap_server,
                                imap_server_port=imap_port,
                                imap_username=email,
                                imap_password=password,
                                smtp_server_host=smtp_server,
                                smtp_server_port=smtp_port,
                                smtp_username=email,
                                smtp_password=password,
                                ssl_required=True)
                
                    print(request.args)
                    
                    print('Adding custom imap smtp account: ', provider)
                    auth_info['email'] = email
                    auth_info['password'] = password
                            
                    if False:
                      account = auth_handler.update_account(account, auth_info)
                    else:
                      account = auth_handler.create_account(email, auth_info)
        
                    try:
                        if auth_handler.verify_account(account):
                            
                            db_session.add(account)
                            status = 'Saved account'

                            query = db_session.query(Namespace)
                            query = query.join(Account)
                            query = query.filter_by(email_address=email)

                            namespace = query.all()[0]
                            account_id = namespace.public_id
                            
                            db_session.commit()
                            
                        else:
                            print('Connection refused to: ' + email)
                            status = 'Connection refused to: ' + email
                    except NotSupportedError as e:
                        print(str(e))
                        status = 'Error in: ' + email
                
            #this is an standar imap smtp account supported with autoresolution like gmail, elbuentono.com.mx, etc
            else:
                print('Adding standar imap smtp account: ', provider)
                auth_info['provider'] = provider
                auth_info['password'] = password
                auth_handler = handler_from_provider(provider)
                
                #initialize the auth object
                #auth_info.update({'email_address': email})
                auth_info.update({'email': email})
                        
                if False:
                  account = auth_handler.update_account(account, auth_info)
                else:
                  account = auth_handler.create_account(email, auth_info)
    
                try:
                    if auth_handler.verify_account(account):
                        
                        db_session.add(account)
                        status = 'Saved account'

                        query = db_session.query(Namespace)
                        query = query.join(Account)
                        query = query.filter_by(email_address=email)

                        namespace = query.all()[0]
                        account_id = namespace.public_id
                        
                        db_session.commit()
                        
                    else:
                        print('Connection refused to: ' + email)
                        status = 'Connection refused to: ' + email
                except NotSupportedError as e:
                    print(str(e))

    encoder = APIEncoder()
    return encoder.jsonify({'email':email, 
                            'status':status,  
                            'account_id':account_id,
                            'authcode':authcode})
    
@app.route('/addaccountauth', methods=['GET'])
def addaccountauth():
    email = request.args.get('email')
    password = request.args.get('password')
    auth_code = request.args.get('auth_code')
    status = None
    namespace = None
    account_id = None
 
    #if we have the imap data we must try to verify the account
    with session_scope(0) as db_session:
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
                
                print('AUTHCODE', auth_code)
                
                auth_info.update(auth_handler.auth_step(auth_code) )
                
                if False:
                    account = auth_handler.update_account(account, auth_info)
                else:
                    print('antes create account')
                    account = auth_handler.create_account(email, auth_info)
                    print('despues create account', account.g_id)
                
                try:
                    print('antes verify')
                    if auth_handler.verify_account(account):
                        print('despues verify')
                        db_session.add(account)
                        status = 'Saved account'
                        
                        query = db_session.query(Namespace)
                        query = query.join(Account)
                        query = query.filter_by(email_address=email)

                        namespace = query.all()[0]
                        account_id = namespace.public_id
                        
                        db_session.commit()
                        
                    else:
                        print('Connection refused to: ' + email)
                        status = 'Connection refused to: ' + email
                except NotSupportedError as e:
                    print(str(e))
    
    encoder = APIEncoder()
    return encoder.jsonify({'email':email, 
                            'password':password, 
                            'account_id':account_id,
                            'status':status, 
                            'authcode':auth_code})
    

from inbox.models.util import delete_namespace
from inbox.heartbeat.status import clear_heartbeat_status
import time

@app.route('/deleteaccount', methods=['GET'])
def deleteaccount():
    email = request.args.get('email')
    
    with session_scope(0) as db_session:
        query = db_session.query(Namespace)
        query = query.join(Account)
        query = query.filter_by(email_address=email)

        namespace = query.all()[0]
        account_id = namespace.id


    with session_scope(account_id) as db_session:
        account = db_session.query(Account).get(account_id)
        
        account.disable_sync("account deleted")
        account.sync_state = 'stopped'
        db_session.commit()

        if not account:
            print 'Account with id {} does NOT exist.'.format(account_id)
            return

        email_address = account.email_address
        namespace_id = account.namespace.id

    print 'Deleting account with id: {}...'.format(account_id)
    start = time.time()

    # Delete data in database
    try:
        print 'Deleting database data'
        delete_namespace(account_id, namespace_id)
    except Exception as e:
        print 'Database data deletion failed! Error: {}'.format(str(e))
        return -1

    database_end = time.time()
    print 'Database data deleted. Time taken: {}'.\
        format(database_end - start)

    # Delete liveness data
    print 'Deleting liveness data'
    clear_heartbeat_status(account_id)

    end = time.time()
    print 'All data deleted successfully! TOTAL time taken: {}'.\
        format(end - start)

    encoder = APIEncoder()
    return encoder.jsonify('DELETED')

import uuid

download_auths = []

@app.route('/getauth', methods=['GET'])
def getauth():
    code = str(uuid.uuid4())
    download_auths.append(code)
    print(download_auths)
    encoder = APIEncoder()
    return encoder.jsonify(code)
    
@app.route('/download', methods=['GET'])
def download():
    code = str(uuid.uuid4())
    download_auths.append(code)
    print(download_auths)
    encoder = APIEncoder()
    return encoder.jsonify(code)
    
    

#
# File downloads
#
@app.route('/downloads', methods=['GET'])
def file_download_api():
    public_id = request.args.get('public_id')
    valid_public_id(public_id)
    try:
        '''
        f = g.db_session.query(Block).filter(
            Block.public_id == public_id,
            Block.namespace_id == g.namespace.id).one()
        '''
        f = g.db_session.query(Block).filter(
            Block.public_id == public_id).one()
    except NoResultFound:
        raise NotFoundError("Couldn't find file {0} ".format(public_id))

    # Here we figure out the filename.extension given the
    # properties which were set on the original attachment
    # TODO consider using werkzeug.secure_filename to sanitize?

    if f.content_type:
        ct = f.content_type.lower()
    else:
        # TODO Detect the content-type using the magic library
        # and set ct = the content type, which is used below
        request.environ['log_context']['no_content_type'] = True
        ct = 'text/plain'
    request.environ['log_context']['content_type'] = ct

    if f.filename:
        name = f.filename
    else:
        request.environ['log_context']['no_filename'] = True
        if ct in common_extensions:
            name = 'attachment.{0}'.format(common_extensions[ct])
        else:
            # HACK just append the major part of the content type
            name = 'attachment.{0}'.format(ct.split('/')[0])

    # TODO the part.data object should really behave like a stream we can read
    # & write to
    try:
        account = g.namespace.account
        statsd_string = 'api.direct_fetching.{}.{}'.format(account.provider,
                                                           account.id)

        response = make_response(f.data)
        statsd_client.incr('{}.successes'.format(statsd_string))

    except TemporaryEmailFetchException:
        statsd_client.incr('{}.temporary_failure'.format(statsd_string))
        log.warning('Exception when fetching email',
                    account_id=account.id, provider=account.provider,
                    logstash_tag='direct_fetching', exc_info=True)

        return err(503, "Email server returned a temporary error. "
                        "Please try again in a few minutes.")
    except EmailDeletedException:
        statsd_client.incr('{}.deleted'.format(statsd_string))
        log.warning('Exception when fetching email',
                    account_id=account.id, provider=account.provider,
                    logstash_tag='direct_fetching', exc_info=True)

        return err(404, "The data was deleted on the email server.")
    except EmailFetchException:
        statsd_client.incr('{}.failures'.format(statsd_string))
        log.warning('Exception when fetching email',
                    logstash_tag='direct_fetching', exc_info=True)

        return err(404, "Couldn't find data on email server.")

    response.headers['Content-Type'] = 'application/octet-stream'  # ct
    # Werkzeug will try to encode non-ascii header values as latin-1. Try that
    # first; if it fails, use RFC2047/MIME encoding. See
    # https://tools.ietf.org/html/rfc7230#section-3.2.4.
    try:
        name = name.encode('latin-1')
    except UnicodeEncodeError:
        name = '=?utf-8?b?' + base64.b64encode(name.encode('utf-8')) + '?='
    response.headers['Content-Disposition'] = \
        'attachment; filename={0}'.format(name)

    request.environ['log_context']['headers'] = response.headers
    return response

    
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
