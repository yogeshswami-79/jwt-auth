const winston = require("winston");

// Create a logger instance
const logger = winston.createLogger({
  level: "info", // Set the logging level
  format: winston.format.simple(), // Set the log format
  transports: [
    new winston.transports.Console(), // Log to the console
    new winston.transports.File({ filename: "requests.log" }), // Log to a file
  ],
});

const loggerRoute = (req, res, next) => {
  const { method, url, params, query, body, ip } = req;
  const {password, ...data} = body;

  const logData = {
    timestamp: new Date().toISOString(),
    method,
    url,
    params,
    query,
    body: data,
    ip,
  };

  logger.info("Request", logData);

  next();
};

module.exports = loggerRoute;