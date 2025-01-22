const express = require('express');
const serverless = require('serverless-http');
const app = express();

// Your existing middleware
app.use(express.json());

// Your existing routes go here
// Example:
app.get('/api/posts', async (req, res) => {
  // Your existing route logic
});

// Export the handler
module.exports.handler = serverless(app);
