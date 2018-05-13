const connectToDatabase = require('../config/db');
const User = require('../users/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs-then');

/* 
 * Functions
 */
module.exports.login = async (event, context) => {
  try {
    context.callbackWaitsForEmptyEventLoop = false;
    await connectToDatabase();
    const session = await login(JSON.parse(event.body));
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

module.exports.register = async (event, context) => {
  try {
    context.callbackWaitsForEmptyEventLoop = false;
    await connectToDatabase();
    const session = await register(JSON.parse(event.body));
    return {
      statusCode: 200,
      body: JSON.stringify(session)
    };
  } catch (error) {
    return {
      statusCode: error.statusCode || 500,
      headers: { 'Content-Type': 'text/plain' },
      body: error.message
    };
  }
};

/* 
 * Helpers
 */
async function login(eventBody) {
  try {
    const user = await User.findOne({ email: eventBody.email });
    if (!user) throw new Error('User with that email does not exists');

    const passIsValid = await comparePassword(
      eventBody.password,
      user.password
    );
    if (!passIsValid) {
      throw new Error('The credentials do not match');
    }
    const token = await signToken(user._id);
    return { auth: true, token };
  } catch (error) {
    return {
      statusCode: error.statusCode || 500,
      headers: { 'Content-Type': 'text/plain' },
      body: error.message
    };
  }
}

function comparePassword(eventPassword, userPassword) {
  return bcrypt.compare(eventPassword, userPassword);
}

async function register(eventBody) {
  try {
    const inputsValid = await checkIfInputIsValid(eventBody);
    if (inputsValid) {
      let user = await User.findOne({ email: eventBody.email });
      if (user) {
        throw new Error('User with that email exists.');
      }
      const hash = await bcrypt.hash(eventBody.password, 8);
      user = await User.create({
        name: eventBody.name,
        email: eventBody.email,
        password: hash
      });
      return { auth: true, token: signToken(user._id) };
    }
  } catch (error) {
    return {
      statusCode: error.statusCode || 500,
      headers: { 'Content-Type': 'text/plain' },
      body: error.message
    };
  }
}

function signToken(id) {
  return jwt.sign({ id: id }, process.env.JWT_SECRET, {
    expiresIn: 86400 // expires in 24 hours
  });
}

function checkIfInputIsValid(eventBody) {
  if (!(eventBody.password && eventBody.password.length >= 7)) {
    throw new Error(
      'Password error. Password needs to be longer than 8 characters.'
    );
  }

  if (
    !(
      eventBody.name &&
      eventBody.name.length > 5 &&
      typeof eventBody.name === 'string'
    )
  )
    throw new Error(
      'Username error. Username needs to longer than 5 characters'
    );

  if (!(eventBody.email && typeof eventBody.name === 'string'))
    throw new Error('Email error. Email must have valid characters.');

  return true;
}
