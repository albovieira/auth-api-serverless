const connectToDatabase = require('../config/db');
const User = require('./user');

/**
 * Functions
 */

module.exports.getUsers = async (event, context) => {
  try {
    context.callbackWaitsForEmptyEventLoop = false;
    await connectToDatabase();
    const users = await getUsers();
    return {
      statusCode: 200,
      body: JSON.stringify(users)
    };
  } catch (error) {
    return {
      statusCode: err.statusCode || 500,
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify({ message: err.message })
    };
  }
};

/**
 * Helpers
 */

async function getUsers() {
  return await User.find({});
}
