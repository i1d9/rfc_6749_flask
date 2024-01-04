from app.oauth import oauth_bp
from flask import jsonify, request, redirect
from app.models.oauth_client import OauthClient
from app.extensions from db
from urllib.parse import urlencode
from datetime import datetime, timedelta

@oauth_bp.route("/authorization", methods=["GET", "POST"])
@login_required
def authorization():
    args = request.args
    client_id = args.get('client_id')
    redirect_uri = args.get('redirect_uri')
    response_type = args.get('response_type')
    code_challenge = args.get('code_challenge')
    code_challenge_method = args.get('code_challenge_method')

    if None not in [client_id, redirect_uri, response_type, code_challenge, code_challenge_method] and code_challenge_method == "S512":
        # Try resolving the client from the database
        client = OauthClient.query.filter_by(
            client_id=client_id, endpoint=redirect_uri).first()

        if client:
            # When a client is found, the request method is POST and the resource owner has accepted the request
            if request.method == "POST" and request.form["accept"] == "1":

                current_time = datetime.now()
                minutes_later = timedelta(minutes=5)
                code = secrets.token_urlsafe(24)
                oauth_code = OauthCode(
                    type=response_type,
                    client_code=code_challenge,
                    client_id=client.id, user_id=current_user.id, expiry_time=current_time + minutes_later, code=code)

                db.session.add(oauth_code)
                db.session.commit()

                parameters = dict(code=oauth_code.code)
                redirect_url = redirect_uri + \
                    ("?" + urlencode(parameters) if parameters else "")

                return redirect(redirect_url)
            # When a client is found, the request method is POST and the resource owner has revoked the request
            elif request.method == "POST" and request.form["accept"] == "0":

                parameters = dict(
                    error="access_denied", error_description="resource owner revoked request")
                redirect_url = redirect_uri + \
                    ("?" + urlencode(parameters) if parameters else "")

                return redirect(redirect_url)
            # When a client is found, the request method is GET
            # This should be the default block that runs then the client is found
            else:

                return render_template('auth/consent.html', client=client)
        else:
            # When the provided params(redirect_uri and client_id) are not associated with a client
            parameters = dict(error="unauthorized_client",
                              error_description="invalid client id and redirect uri")
            redirect_url = redirect_uri + \
                ("?" + urlencode(parameters) if parameters else "")
            return redirect(redirect_url)

    elif redirect_uri is not None:
        # When the provided request params are invalid/dont contain all required params
        parameters = dict(error="invalid_request")
        redirect_url = redirect_uri + \
            ("?" + urlencode(parameters) if parameters else "")

        return redirect(redirect_url)

    # Ultimately redirect to the home page
    return redirect(url_for('index'))


@oauth_bp.post("/token")
@csrf.exempt
def access_token_endpoint():
    args = request.json

    grant_type = args.get('grant_type')
    code = args.get('code')
    redirect_uri = args.get('redirect_uri')
    client_id = args.get('client_id')
    code_verifier = args.get('code_verifier')

    if None not in [client_id, redirect_uri, grant_type, code, code_verifier]:
        # Try resolving the client from the database
        client = OauthClient.query.filter_by(
            client_id=client_id, endpoint=redirect_uri).first()
        data = {}
        current_time = datetime.now()
        hour_later = timedelta(hours=1)
        if client:
            match grant_type:
                case "authorization_code":
                    if None not in [code_verifier, code]:

                        oauth_code = OauthCode.query.filter_by(
                            code=code,
                            client_id=client.id,  type="authorization_code").first()

                        hash = hashlib.sha512(
                            code_verifier.encode('UTF-8')).digest()

                        computed_challenge = base64.urlsafe_b64encode(
                            (hash)).decode("utf-8")

                        if oauth_code and oauth_code.client_code == computed_challenge and oauth_code.expiry_time > current_time:

                            encoded_jwt = jwt.encode(
                                {'user_id': str(oauth_code.user_id)}, 'secret', algorithm='HS512')

                            access_token = OauthCode(
                                type="access_token",
                                client_id=client.id, user_id=oauth_code.user_id, expiry_time=current_time + hour_later, code=encoded_jwt)

                            data = {
                                "access_token": access_token.code,
                                "token_type": "Bearer",
                                "expires_in": 3600,
                            }
                        else:

                            data = {"error": "invalid_request",
                                    "error_description": "invalid parameters provided",
                                    }
                    else:
                        data = {"error": "invalid_request",
                                "error_description": "invalid parameters provided",
                                }

                case "password":
                    data = {
                        "access_token": "2YotnFZFEjr1zCsicMWpAA",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                case "client_credentials":
                    data = {
                        "access_token": "2YotnFZFEjr1zCsicMWpAA",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                case _:
                    data = {
                        "access_token": "2YotnFZFEjr1zCsicMWpAA",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }

        return jsonify(data)

    data = {"error": "invalid_request",
            "error_description": "invalid parameters provided",
            }

    return jsonify(data)
