const jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
const connectToDatabase = require('../config/db');
const User = require('../users/user');

// Policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

module.exports.auth = (event, context, callback) => {
  // check header or url parameters or post parameters for token
  const token = event.authorizationToken;

  if (!token) return callback(null, 'Unauthorized');

  // verifies secret and checks exp
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return callback(null, 'Unauthorized');

    // if everything is good, save to request for use in other routes
    return callback(null, generatePolicy(decoded.id, 'Allow', event.methodArn));
  });
};

module.exports.me = async (event, context) => {
  try {
    context.callbackWaitsForEmptyEventLoop = false;
    await connectToDatabase();
    const session = await me(event.requestContext.authorizer.principalId); // the decoded.id from the VerifyToken.auth will be passed along as the principalId under the authorizer
    if (!session) {
      throw new Error('No user found');
    }
    return {
      statusCode: 200,
      body: JSON.stringify(session)
    };
  } catch (error) {
    return {
      statusCode: error.statusCode || 500,
      headers: { 'Content-Type': 'text/plain' },
      body: { stack: error.stack, message: error.message }
    };
  }
};

/*
* Helpers
*/
function me(userId) {
  return User.findById(userId, { password: 0 });
}
