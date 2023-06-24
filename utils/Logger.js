const winston = require('winston');

// Create a logger instance
const logger = winston.createLogger({
  level: 'info', // Set the logging level
  format: winston.format.simple(), // Set the log format
  transports: [
    new winston.transports.Console(), // Log to the console
    new winston.transports.File({ filename: 'app.log' }) // Log to a file
  ]
});


module.exports = logger;

// Log messages at different levels
// logger.error('An error occurred');
// logger.warn('Warning: Something is not right');
// logger.info('Informational message');
// logger.debug('Debugging information');

// You can also log additional metadata
// logger.info('User logged in', { username: 'john.doe', userId: 123 });
