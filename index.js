'use strict';
const querystring = require('querystring');

const 
base64url = require('base64url'),
crypto    = require('crypto'),
dotenv    = require('dotenv'),
express   = require('express'),
app       = express();

const
express_session = require('express-session');

dotenv.config();

const {
  MSA_SERVICE_PORT,
  MSA_SERVICE_HOST,
  MSA_DB_CLIENT,
  MSA_DB_USER,
  MSA_DB_PASSWORD,
  MSA_DB_DATABASE,
  MSA_DB_PORT,
  MSA_DB_HOST,
  MSA_CREATE_WWW_APP,
  MSA_CREATE_ADMIN_APP,
  MSA_CREATE_GATEWAY_APP,
  MSA_AUTH_SESSION_SECRET,
  MSA_AUTH_USE_REDIS,
  MSA_STATIC_SERVICE_URL,
} = process.env;

if (!MSA_AUTH_SESSION_SECRET)
  throw new Error([
    'You must configure a session secret to use',
    'the authentication service'
  ].join(' '));

if (MSA_AUTH_USE_REDIS) {

  const RedisSessionStore = require('connect-redis')(express_session);

  app.use(express_session({
    store  : new RedisSessionStore(),
    secret : MSA_AUTH_SESSION_SECRET,
    resave : false,
    saveUninitialized: false,
  }));

}
// maybe allow other session stores?
// defaults to in-memory for testing
else {

  app.use(express_session({
    secret : MSA_AUTH_SESSION_SECRET,
    resave : false,
  }));

}

let model = null;

const initModel = require('./lib/model');

(async () => {

  model = await initModel({
    MSA_DB_CLIENT,
    MSA_DB_USER,
    MSA_DB_PASSWORD,
    MSA_DB_DATABASE,
    MSA_DB_PORT,
  });

  if (
    MSA_CREATE_GATEWAY_APP ||
    MSA_CREATE_WWW_APP     || 
    MSA_CREATE_ADMIN_APP) {


    if (!await model.ownerExists({name: 'msa'})) {

      const password = crypto.randomBytes(32).toString('hex');

      // create super user for applications to operate through
      // client_credentials grant type.
      const msaOwner = await model.createOwner({
        name: 'msa',
        password
      });

      console.log([
        'created msa user for bootstrapped apps',
        'be sure to write this down, as it is now encrypted',
        'and won\'t be retrievable from DB'
      ].join(' '));

      console.log('\tname %s', msaOwner.name);
      console.log('\tpassword %s', password);

    }

  }

  const bootstrapApps = {
    'MSA API Gateway': MSA_CREATE_GATEWAY_APP,
    'MSA WWW'        : MSA_CREATE_WWW_APP,
    'MSA Admin'      : MSA_CREATE_ADMIN_APP,
  };

  const appLabels = Object.keys(bootstrapApps);

  const promisedBootstraps = appLabels.map(async (label) => {

    const
    APP_EXISTS = await model.applicationExists({label}),
    CREATE_APP = bootstrapApps[label] || false;

    // confidential applications
    if (CREATE_APP && !APP_EXISTS) {

      console.log('creating application : %s', label);

      const application = await model.createApplication({
        label,
        client_type: 'confidential',
        owner_name : 'msa'
      });

      console.log([
        'application created. be sure to write down secret',
        'somewhere safe. This is now password encrypted in the',
        'database, so it will be irretrievable after this.'
      ].join(' '));

      console.log('\tname: %s', application.name);
      console.log('\tclient_id: %s', application.client_id);
      console.log('\tsecret: %s', application.plainSecret);

    }

    return false;

  });

  Promise.all(promisedBootstraps)
  .catch((e) => {

    console.error(e);
  
  });

})();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'pug');
app.set('views', './views');

const {
  wrapAsync,
  msaStatic
} = require('msa-shared');

msaStatic(MSA_STATIC_SERVICE_URL,app);

app.get('/test', (req, res) => {

  res.render('test.pug');

});

// POST /token 
// get access token for application
app.post('/token', wrapAsync(async (req, res, next) => {

  const headers = req.headers || {};

  const authorization = headers.authorization || null;

  if (!authorization) {
    next({message: 'invalid grant'});
  }

  const [auth_type, auth_code] = authorization.split(' ');

  // using this endpoint assumes use of 'Basic' header
  if (auth_type !== 'Basic') {
    next({message: 'invalid auth type'});
  }

  const [client_id, client_secret] = base64url.decode(auth_code).split(':');

  if (!client_id || !client_secret) {
    next({message: 'invalid grant'});
  }

  const body = req.body || {};

  const params = Object.assign({}, body);

  const grant_type = params.grant_type || 'client_credentials';

  params.client_id     = client_id;
  params.client_secret = client_secret;

  console.log('%o', params);

  if (grant_type === 'authorization_code') {

    const token = await model.getAuthorizationCodeToken(params)
    .catch((e) => {throw e});

    return res.json(token);

  }

  else if (grant_type === 'password') {

    const token = await model.getPasswordToken(params)
    .catch((e) => {throw e});

    return res.json(token);

  }

  else if (grant_type === 'client_credentials') {

    const token = await model.getClientCredentialsToken(params)
    .catch((e) => {throw e});

    return res.json(token);

  }

  else if (grant_type === 'implicit')  {

    const token = await model.getImplicitToken(params)
    .catch((e) => {throw e});

    return res.json(token);

  }
  else
    next({message: 'invalid grant_type'});

  const token = await model.getAccessToken(body)
  .catch(next);

  res.json(token);
  
}));

// get scope of token
app.get('/scope', wrapAsync(async(req, res) => {

}));

// allows delgation of authorization on behalf of resource owner
app.get('/auth', wrapAsync(async (req, res) => {

  const query = req.query || {};

  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
  } = query;

  // check if client can use authorization code flow
  const can = await model.applicationCanUseFlow({
    client_id,
    grant_type: 'authorization_code'
  })
  .catch((e) => {throw e});

  if (!can)
    throw new Error('unauthorized_client');

  const application = await model.getApplication({client_id});

  if (!application)
    throw new Error('invalid_client');

  // check if user has session
  const
  session = req.session || {},
  currentUser = session.currentUser || null;

  // user does not have a session. redirect to the sign in
  // page, using the current url as a 'next' value
  if (currentUser === null) {

    // param used to redirect after sign in
    const next = [
      'next=', req.protocol, '://', req.get('host'), req.originalUrl
    ].join('');

    // redirect to sign in form
    return res
      .status(302)
      .redirect(['/sign-in', next].join('?'));

  }

  res.render('auth.pug', {
    pageTitle : [application.label, 'Would like Access'].join(' '),
    scope, 
    client_id,
    redirect_uri,
    state,
    state,
  });

}));

app.get('/sign-in', wrapAsync(async (req, res) => {

  const
  query = req.query  || {},
  next  = query.next || null;

  // TODO: check referer to make sure 'next' came from here?

  res.render('sign-in.pug', {
    next,
  }); 

}));

app.post('/auth', wrapAsync(async (req, res) => {

  const body = req.body || {};

  // did user authorize app 
  const 
  authorize    = body.authorize || 'false',
  redirect_uri = body.redirect_uri,
  client_id    = body.client_id;

  // get create grant

}));

app.post('/application', wrapAsync(async (req, res) => {

  const body = req.body || {};

  const application = await model.createApplication(body)
    .catch(next);

  if (application)
    res.json(application);
  
}));

// allow registration of resource via other services
app.post('/resource', wrapAsync(async (req, res) => {

  const body = req.body || {};

  const result = await model.createResource(body)
    .catch(next);

  res.json({

  });

}));

app.post('/owner', wrapAsync(async (req, res) => {

  const body = req.body || {};

  const owner = await model.createOwner(body)
    .catch(next);

  if (owner)
    res.json(owner);

}));

app.post('/owner/resource', wrapAsync(async (req, res, next) => {

  const body = req.body || {};

  const success = await model.grantOwnerResources(body)
    .catch(next);

  if (!success)
    return res.end();

  res.json(success);

}));


// err handler
app.use((err, req, res, next) => {

  // TODO: handle other status codes based
  // on error object
  console.error('%o', err);

  res.status(400).json({
    success: false,
    message: err.message
  });

});


app.get('/service', wrapAsync(async () => {

  res.json({
    'POST /auth'           : {},
    'GET /scope'           : {},
    'GET /delegate'        : {},
    'POST /delegate'       : {},
    'POST /application'    : {},
    'POST /resource'       : {},
    'POST /owner'          : {},
    'POST /owner/resource' : {}
  });
  
}));

app.get('*', (req, res) => {

  res.end();

});

app.listen(MSA_SERVICE_PORT, MSA_SERVICE_HOST);

