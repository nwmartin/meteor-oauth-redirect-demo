// We're overriding the behavior of
// meteor/packages/accounts-oauth-helper/oauth_server.js
// to allow for not having the popup window behavior.

(function () {
  var connect = __meteor_bootstrap__.require("connect");

  Accounts.oauth._services = {};

  // When we get an incoming OAuth http request we complete the oauth
  // handshake, account and token setup before responding.  The
  // results are stored in this map which is then read when the login
  // method is called. Maps state --> return value of `login`
  //
  // XXX we should periodically clear old entries
  Accounts.oauth._loginResultForState = {};

  Accounts.oauth._middleware = function (req, res, next) {
    // Make sure to catch any exceptions because otherwise we'd crash
    // the runner
    try {
      var serviceName = oauthServiceName(req);
      if (!serviceName) {
        // not an oauth request. pass to next middleware.
        next();
        return;
      }

      var service = Accounts.oauth._services[serviceName];

      // Skip everything if there's no service set by the oauth middleware
      if (!service) {

        // Since we're doing redirects now, the service isn't going to exist.
        // Right now we just flat out recreate google like from scratch, but later on
        // we might want to do something smart here.
        registerGoogle();
        service = Accounts.oauth._services[serviceName];

        if (!service) {
          throw new Error("Unexpected OAuth service " + serviceName);
        }
      }

      // Make sure we're configured
      ensureConfigured(serviceName);

      if (service.version === 1) {
        Accounts.oauth1._handleRequest(service, req.query, res);
      }
      else if (service.version === 2) {
        Accounts.oauth2._handleRequest(service, req.query, res);
      }
      else
        throw new Error("Unexpected OAuth version " + service.version);
    } catch (err) {
      // if we got thrown an error, save it off, it will get passed to
      // the approporiate login call (if any) and reported there.
      //
      // The other option would be to display it in the popup tab that
      // is still open at this point, ignoring the 'close' or 'redirect'
      // we were passed. But then the developer wouldn't be able to
      // style the error or react to it in any way.
      if (req.query.state && err instanceof Error)
        Accounts.oauth._loginResultForState[req.query.state] = err;

      // also log to the server console, so the developer sees it.
      Meteor._debug("Exception in oauth request handler", err);

      // XXX the following is actually wrong. if someone wants to
      // redirect rather than close once we are done with the OAuth
      // flow, as supported by
      // Accounts.oauth_renderOauthResults, this will still
      // close the popup instead. Once we fully support the redirect
      // flow (by supporting that in places such as
      // packages/facebook/facebook_client.js) we should revisit this.
      //
      // close the popup. because nobody likes them just hanging
      // there.  when someone sees this multiple times they might
      // think to check server logs (we hope?)
      closePopup(res);
    }
  };

  // Handle /_oauth/* paths and extract the service name
  //
  // @returns {String|null} e.g. "facebook", or null if this isn't an
  // oauth request
  var oauthServiceName = function (req) {

    // req.url will be "/_oauth/<service name>?<action>"
    var barePath = req.url.substring(0, req.url.indexOf('?'));
    var splitPath = barePath.split('/');

    // Any non-oauth request will continue down the default
    // middlewares.
    if (splitPath[1] !== '_oauth') {
      return null;
    }

    // Find service based on url
    var serviceName = splitPath[2];
    return serviceName;
  };

  // Make sure we're configured
  var ensureConfigured = function(serviceName) {
    if (!Accounts.loginServiceConfiguration.findOne({service: serviceName})) {
      throw new Accounts.ConfigError("Service not configured");
    };
  };

  Accounts.oauth._renderOauthResults = function(res, query) {
    // We support ?close and ?redirect=URL. Any other query should
    // just serve a blank page
    if ('close' in query) { // check with 'in' because we don't set a value
      closePopup(res, query);
    } else if (query.redirect) {
      res.writeHead(302, {'Location': query.redirect});
      res.end();
    } else {
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end('', 'utf-8');
    }
  };

  // We've snagged this to dump out the authState for a user and dump them back
  // to the login page with just enough information to log in.
  var closePopup = function(res, query) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    var content =
      '<html><head><script>window.location.href="/?authState=' + query.state + '"</script></head></html>';
    res.end(content, 'utf-8');
  };

  // Hack to force reregisteration of google if it's not live, like say, after
  // one of our redirects.
  var registerGoogle = function () {
    Accounts.oauth.registerService('google', 2, function(query) {

      var response = getTokens(query);
      var accessToken = response.accessToken;
      var identity = getIdentity(accessToken);

      var serviceData = {
        id: identity.id,
        accessToken: accessToken,
        email: identity.email,
        expiresAt: (+new Date) + (1000 * response.expiresIn)
      };

      // only set the token in serviceData if it's there. this ensures
      // that we don't lose old ones (since we only get this on the first
      // log in attempt)
      if (response.refreshToken)
        serviceData.refreshToken = response.refreshToken;

      return {
        serviceData: serviceData,
        options: {profile: {name: identity.name}}
      };
    });

    // returns an object containing:
    // - accessToken
    // - expiresIn: lifetime of token in seconds
    // - refreshToken, if this is the first authorization request
    var getTokens = function (query) {
      var config = Accounts.loginServiceConfiguration.findOne({service: 'google'});
      if (!config)
        throw new Accounts.ConfigError("Service not configured");

      console.log('Prepare for post.');
      var result = Meteor.http.post(
        "https://accounts.google.com/o/oauth2/token", {params: {
          code: query.code,
          client_id: config.clientId,
          client_secret: config.secret,
          redirect_uri: Meteor.absoluteUrl("_oauth/google?close"),
          grant_type: 'authorization_code'
        }});

      if (result.error) // if the http response was an error
        throw result.error;
      if (result.data.error) // if the http response was a json object with an error attribute
        throw result.data;

      return {
        accessToken: result.data.access_token,
        refreshToken: result.data.refresh_token,
        expiresIn: result.data.expires_in
      };
    };

    var getIdentity = function (accessToken) {
      var result = Meteor.http.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        {params: {access_token: accessToken}});

      if (result.error)
        throw result.error;
      return result.data;
    };
  };
})();
