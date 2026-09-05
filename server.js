const express = require('express');
const path = require('path');
const app = require('./api/index.js');

// Serve the PROMO HUB web app from /public.
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

module.exports = app;
