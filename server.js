const express = require('express');

const logger = require('./lib/logger');
const { connectToDB } = require('./lib/mongo');
const apiRouter = require('./api');

const app = express();
const port = process.env.PORT || 8000;

app.use(express.json());
app.use(logger);

app.use('/', apiRouter);

app.use('*', (req, res, next) => {
  res.status(404).send({
    err: "The path " + req.originalUrl + " doesn't exist"
  });
});

connectToDB(() => {
  app.listen(port, () => {
    console.log("== Server is listening on port:", port);
  });
});
