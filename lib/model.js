////// AUTH MODEL
'use strict';

//// Contrib Modules
const 
base64url = require('base64url'),
bcrypt    = require('bcrypt'),
knex      = require('knex'),
moment    = require('moment');

//// Core Modules
const
crypto = require('crypto');


//// Custom Modules
const {
  machineName,
  knexResponseHandler
} = require('msa-shared');


//// DB Boostrap
const bootstrap = async (dba) => {

  // resource owner
  (await dba.schema.hasTable('owner')) ||
  await dba.schema.createTable('owner', (table) => {

    table.increments()

    // user name.
    table.string('name', 100)
      .unique()
      .notNullable();

    table.string('hash', 60)
      .notNullable();

  });

  (await dba.schema.hasTable('client_type')) ||
  await dba.schema.createTable('client_type', (table) => {

    table.string('name', 32) 
      .primary();

  }) &&
  await dba('client_type').insert([
    {name: 'public'}, 
    {name: 'confidential'}, 
  ]);

  // client applications
  (await dba.schema.hasTable('application')) ||
  await dba.schema.createTable('application', (table) => {

    table.increments();

    table.string('name', 255)
      .unique()
      .notNullable();

    table.string('label', 255)
      .unique()
      .notNullable();

    table.string('client_id', 255)
      .unique()
      .notNullable();

    table.string('client_secret', 255)
      .notNullable();

    table.string('client_type', 32)
      .defaultTo('public');
    
    table.foreign('client_type')
      .references('client_type.name');

    // comma separated list of URIs used by app
    table.string('redirect_uris', 255);

    // user who owns the application
    table.integer('owner_id', 10)
      .unsigned()
      .notNullable();

    table.foreign('owner_id')
      .references('owner.id')

    table.timestamps(false, true);

  });

  // resources
  (await dba.schema.hasTable('resource')) ||
  (await dba.schema.createTable('resource', (table) => {

    table.string('name', 100)
      .primary()
      .unique()
      .notNullable();

    table.string('label', 100)
      .unique()
      .notNullable();

  })) &&
  // create resources for the auth server
  dba('resource').insert([
    {name: 'resource', label: 'Resource'},
    {name: 'owner', label: 'Owner'},
    {name: 'application', label: 'Application'},
  ]);

  (await dba.schema.hasTable('grant_type')) ||
  await dba.schema.createTable('grant_type', (table) => {

    table.string('name', 32)
      .primary();

  }) &&
  await dba('grant_type').insert([
    {name: 'client_credentials'},
    {name: 'password'},
    {name: 'authorization_code'},
    {name: 'implicit'},
    {name: 'refresh'},
  ]);

  // authorization grants
  (await dba.schema.hasTable('grant')) ||
  await dba.schema.createTable('grant', (table) => {

    table.bigIncrements();

    table.string('code', 255)
      .unique();

    table.string('application_client_id', 255)
      .notNullable();

    table.foreign('application_client_id')
      .references('application.client_id');

    table.string('grant_type', 32)
      .notNullable();

    table.foreign('grant_type')
      .references('grant_type.name');

    table.integer('owner_id', 10)
      .notNullable()
      .unsigned()

    table.foreign('owner_id')
      .references('owner.id');

    table.index(['application_client_id', 'owner_id']);

    table.text('scope', 'longtext');

    table.string('redirect_uri', 255);

    table.boolean('revoked')
      .defaultTo(false);

    table.timestamps(false, true);

  });

  (await dba.schema.hasTable('token')) ||
  await dba.schema.createTable('token', (table) => {

    table.bigIncrements();

    table.bigInteger('grant_id')
      .unsigned()
      .notNullable();

    table.foreign('grant_id')
      .references('grant.id');

    table.string('access_token', 255)
      .unique()
      .notNullable();

    table.string('refresh_token', 255)
      .unique()
      .notNullable();

    table.datetime('expires', 6)
      .notNullable();

    table.timestamps(false, true);

  });

  (await dba.schema.hasTable('resource_permission')) ||
  await dba.schema.createTable('resource_permission', (table) => {

    table.string('name', 32)
      .primary();

  }) &&
  await dba('resource_permission').insert([
    {name: 'READ'},   
    {name: 'WRITE'},   
    {name: 'DELETE'},   
    {name: 'ADMIN'},   
  ]);

  (await dba.schema.hasTable('resource_owner')) ||
  await dba.schema.createTable('resource_owner', (table) => {

    table.integer('owner_id', 10)
      .unsigned()
      .notNullable();

    table.string('resource_permission', 32)
      .defaultTo('READ');

    table.string('resource_name', 100)
      .notNullable();

    table.foreign('resource_permission')
      .references('resource_permission.name');

    table.foreign('owner_id')
      .references('owner.id');

    table.foreign('resource_name')
      .references('resource.name');

    table.primary(['owner_id', 'resource_name']);
    
  });

};

const init = async (config) => {

  const dba = await knex({
    client: config.MSA_DB_CLIENT, 
    connection : {
      user     : config.MSA_DB_USER,
      password : config.MSA_DB_PASSWORD,
      database : config.MSA_DB_DATABASE,
      host     : config.MSA_DB_HOST,
      port     : config.MSA_DB_PORT
    },
    postProcessResponse: knexResponseHandler
  });

  await bootstrap(dba);

  const model = {};

  model.applicationCanUseFlow = async (params) => {

    const
    client_id  = params.client_id  || null,
    grant_type = params.grant_type || null;

    const application = await model.getApplication({client_id}); 

    if (!application)
      throw new Error('invalid_client');

    const client_type = application.client_type;

    if (!(client_type in clientGrantMap))
      throw new Error('unauthorized_client');

    if (!(grant_type in clientGrantMap[client_type]))
      throw new Error('unauthorized_client');

    return true;

  };

  model.getApplication = async (params) => {

    const client_id = params.client_id || null;

    return dba
      .select('name', 'label', 'client_type', 'client_id')
      .from('application')
      .where({client_id});

  };

  model.applicationExists = async (params) => {

    const usedParams = {};

    params.id    && (usedParams.id    = params.id);
    params.label && (usedParams.label = params.label);
    params.name  && (usedParams.name  = params.name);

    if (Object.keys(params).length == 0)
      return false;

    return dba
      .select('id')
      .from('application')
      .where(usedParams)
      .then((res) => res && true);

  };

  // register an application to use authentication server
  model.createApplication = async (params) => {

    const
    label       = params.label,
    client_type = params.client_type || 'public';

    const name = machineName(label);
    const client_id = base64url(crypto.randomBytes(64));
    const plainSecret = base64url(crypto.randomBytes(64));

    // allow owner name or id to be used.
    const 
    owner_name = params.owner_name || null;

    let owner_id = null;

    if (!params.owner_id && owner_name) {

      const {id} = await dba
        .select('id')
        .from('owner')
        .where({name: owner_name});

      owner_id = id;

    }
    else if (params.owner_id) {

      owner_id = id;

    }
    else {

      throw new Error('Owner ID required to register application');

    }

    let redirect_uris = params.redirect_uris || '';

    redirect_uris = redirect_uris.trim();

    // password encrypt the secret
    const client_secret = await bcrypt.hash(plainSecret, 12);

    const id = await dba('application').insert({
      client_id,
      client_secret,
      client_type,
      label,
      name,    
      owner_id,
      redirect_uris,
    })
    .catch((e) => {

      throw e;

    });

    if (id) {
      return dba
      .select(
        'name',
        'label',
        'client_id',
        'redirect_uris',
        'client_type'
      )
      .from('application')
      .where({id})
      .then((result) => {

        // give back plain secret just this once
        // to ensure client knows their own secret
        result.plainSecret = plainSecret;

        return result;
        
      });
    }

  };

  const clientGrantMap = {
    public : {
      authorization_code : true,
      client_credentials : false,
      password           : false,
      implicit           : true,
      refresh            : true 
    },
    confidential: {
      authorization_code : true,
      client_credentials : true,
      password           : true,
      implicit           : false,
      refresh            : true 
    }
  };

  const authenticateOwner = async (owner_name, password) => {

    const owner = await dba
      .select('name', 'hash')
      .from('owner')
      .where({name: owner_name});

    return bcrypt.compare(password, owner.hash);

  };

  // checks if the application client_id and secret are correct.
  // additionally throws error if the grant_type is not allowed
  // for the application client_type (public, confidential)
  const authenticateApplication = async (params) => {

    const
    client_secret = params.client_secret || null,
    client_id     = params.client_id     || null,
    redirect_uri  = params.redirect_uri  || null;

    if (client_secret === null)
      throw new Error('invalid_request');

    if (client_id === null)
      throw new Error('invalid_request');

    const application = await dba
      .select(
        'client_id',
        'client_type',
        'client_secret',
        'redirect_uris'
      )
      .from('application')
      .where('client_id', '=', client_id)
      .catch((e) => {

        console.error('Error retrieving application %o', e);

        return [];

      });

    if (!application)
      throw new Error('unauthorized_client');

    const 
    client_type = application.client_type,
    grant_type  = params.grant_type;

    // only allow certain grant types for different client types
    if (!grant_type || !clientGrantMap[client_type][grant_type])
      throw new Error('unsupported_grant_type');

    // these require a redirect uri.
    if (grant_type in {authorization_code: true, implicit: true}) {

      if (!application.redirect_uris)
        throw new Error([
          'application needs redirect URI to use',
          'this authorization flow'
        ].join(' '));

      const
      redirect_uris = application.redirect_uris,
      uri_tokens    = redirect_uris.split(',');

      const norm_uris = uri_tokens.reduce((o, uri) => {

        o[uri.trim().toLowerCase()] = true;

        return o;

      }, {});

      if (! (redirect_uri.trim().toLowerCase() in norm_uris)) {
        throw new Error([
          'invalid_request'
        ].join(' '));
      }

    }

    return bcrypt.compare(client_secret, application.client_secret);

  };

  model.getClientCredentialsToken = async (params) => {

    const secretValid = await authenticateApplication(params)
      .catch((e) => {throw e});

    if (!secretValid)
      throw new Error('invalid_client');

    const {client_id} = params;

    // get application
    const application = await dba
      .select('owner.name AS owner_name')
      .from('application')
      .innerJoin('owner', 'application.owner_id', '=', 'owner.id')
      .where({client_id});

    // use the application's owner as the person we are granting for
    const grant = await createOrGetGrant({
      client_id,
      owner_name : application.owner_name,
      grant_type : 'client_credentials'
    });

    if (!grant)
      throw new Error('invalid_grant');

    console.log('%o', grant);

    const grant_id = grant.id;

    const refresh_token = params.refresh_token || null;

    return createOrGetToken({grant_id, refresh_token});

  }; 

  const createAuthCodeGrant = async (params) => {

    // check the client_id, secret, redirect uri, client_type
    const secretValid = await authenticateApplication(params)
      .catch((e) => {throw e});

    if (!secretValid)
      throw new Error('invalid_client');

    const {
      username,
      password,
    } = params;

    if (!authenticateOwner(username, password))
      throw new Error([
        'invalid_grant'
      ].join(' '));

    // return created grant to index so a redirect can
    // be performed
    return createOrGetGrant({
      client_id    : params.client_id,  
      owner_name   : params.username,
      grant_type   : 'authorization_code',
      redirect_uri : params.redirect_uri,
      scope        : params.scope,
    });

  };

  const getGrant = async (params) => {

    const {
      owner_name,
      client_id,
      grant_type
    } = params;

    // see if the grant exists for the client_id owner_id combo
    const owner = await dba
      .select('id')
      .from('owner')
      .where('name', '=', owner_name);

    return dba
    .select('id', 'application_client_id', 'owner_id', 'scope', 'redirect_uri')
    .from('grant')
    where({
      application_client_id: client_id,
      owner_id : owner.id,
      grant_type,
    });

  };

  const createOrGetGrant = async (params) => {

    const {
      owner_name,
      client_id,
      grant_type,
      redirect_uri,
      scope
    } = params;

    const existingGrant = await getGrant({
      owner_name, 
      client_id
    });

    // grant was revoked by client
    if (existingGrant && existingGrant.revoked) {
      throw new Error([
        'invalid_grant'
      ].join(' '));
    }
    else if (existingGrant) { 

      // update expiry for grant
      return existingGrant;

    }

    const owner = await dba
      .select('id')
      .from('owner')
      .where('name', '=', owner_name);

    const grant_id = await dba('grant').insert({
      application_client_id: client_id,  
      owner_id: owner.id,
      grant_type,
      redirect_uri,
      scope,
    })
    .catch((e) => {

      throw e;
      
    });

    if (!grant_id) return null;

    return dba
      .select('id', 'scope') 
      .from('grant')
      .where({id : grant_id});

  };

  const createOrGetToken = async (params) => {

    const {
      grant_id,
    } = params;

    const token = await dba
      .select('id', 'access_token', 'refresh_token', 'expires')
      .from('token')
      .where({grant_id});

    if (token && moment().isSameOrAfter(moment(token.expires))) {

      const token_id = token.id;

      const refresh_token = params.refresh_token;

      if (refresh_token && token.refresh_token === refresh_token) {

        return refreshToken(refresh_token);

      }

      throw new Error([
        'invalid_grant'
      ].join(' '));

    }
    else if (token) {

      token.token_type = "bearer"

      // set expires_in to seconds
      token.expires_in = (+moment(token.expires) - Date.now()) / 1000;

      // token still valid, return token
      return token;

    }

    // no token. create the token
    const expires = Date.now() + 60 * 60 * 1000;

    const 
    access_token  = base64url(crypto.randomBytes(64)),
    refresh_token = base64url(crypto.randomBytes(64));

    const id = await dba('token')
      .insert({
        grant_id,  
        access_token,
        refresh_token,
        expires : moment(expires).format('YYYY-MM-DD HH:mm:ss')
      });

    return dba
    .select('access_token', 'refresh_token', 'expires')
    .from('token')
    .where({id})
    .then((result) => {

      result.token_type = "bearer"

      // set expires_in to seconds
      result.expires_in = (expires - Date.now() ) / 1000;

      return result;
      
    });

  };

  const refreshToken = async (refresh_token) => {

    const expires = Date.now() + 60 * 60 * 1000;

    const newAccessToken = base64url(crypto.randomBytes(64));

    console.log('refreshing token');

    await dba('token')
    .update({
      expires: moment(expires).format('YYYY-MM-DD HH:mm:ss'),
      access_token : newAccessToken
    })
    .where({refresh_token: refresh_token})
    .catch((e) => {

      // TODO: try again on duplicate accesstoken error
      throw e;

    });

    return dba
    .select(
      'access_token',
      'refresh_token',
      'expires'
    )
    .from('token')
    .where('refresh_token', '=', refresh_token)
    .then((result) => {

      result.expires_in = (Date.now() - expires) / 1000;

      return result;

    });

  };

  // allow client to explicitly set grant_type='refresh'
  // this will refresh the token using refresh_token
  model.getRefreshToken = async (params) => {

    const grant_id = params.grant_id;

    const expires = Date.now() + 60 * 60 * 1000;

    return Promise.all([
      dba('grant')
        .update({expires})
        .where({id: grant_id}),
      dba('token')
        .update({expires})
        .where({grant_id})
    ]);

  };

  // flow for grant_type === 'authorization_code'
  model.getAuthorizationCodeToken = async (params) => {

    const {
      auth_code,
      redirect_uri,
    } = params;

    // see if the grant exists. It should
    const grant = await dba
      .select(
        'id', 
        'redirect_uri'
      )
      .from('grant')
      .where('code', '=', auth_code);

    if (!grant)
      throw new Error('invalid_client');

    if (grant.redirect_uri !== redirect_uri)
      throw new Error('invalid_client');

    const grant_id = grant.id;

    const refresh_token = params.refresh_token || null;

    return createOrGetToken({grant_id, refresh_token});

  };

  // flow for grant_type === 'password'
  model.getPasswordToken = async (params) => {

    const client_id = params.client_id; 

    const application = await dba
      .select('client_type')
      .from('application')
      .where({client_id});

    if (!clientGrantMap[application.client_type]['password'])
      throw new Error('unauthorized_client');

    // use the resource owner name and password
    const {
      username,
      password
    } = params;

    if (!await authenticateOwner(username, password)) {
      throw new Error([
        'invalid_grant'
      ].join(' '));
    }

    // create the password grant
    const grant = await createOrGetGrant({
      owner_name  : username,
      client_id   : params.client_id,
      grant_type  : 'password'
    })
    .catch((e) => {

      throw e; 

    });

    const grant_id = grant.id;

    const refresh_token = params.refresh_token || null;

    return createOrGetToken({grant_id, refresh_token});

  };

  model.ownerExists = async (params) => {

    const usedParams = {};

    params.id && (usedParams.id = params.id);
    params.name && (usedParams.name = params.name);

    if (!Object.keys(usedParams).length)
      return false;

    return dba.select('id')
      .from('owner')
      .where(usedParams)
      .then((res) => res && true);

  };
  
  model.createOwner = async (params) => {

    const password = params.password;

    delete params.password;

    const hash = await bcrypt.hash(password, 12);

    const {
      name,
    } = params;

    const id = await dba('owner').insert({
      name, 
      hash
    });

    return dba
      .select()
      .from('owner')
      .where({id});

  };


  return model;

};

module.exports = init;
