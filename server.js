const app = require('express')();
const bodyParser = require('body-parser');
const swaggerUi = require('swagger-ui-express'), swaggerDocument = require('./swagger.json');
const cors = require('cors')({ origin: true });

const authRoute = require('./util/routes/auth');
const userRoute = require('./util/routes/user');
const chatRoute = require('./util/routes/chat');

app.use(cors)

app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", '*');
    res.header("Access-Control-Allow-Credentials", true);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header("Access-Control-Allow-Headers", 'Origin,X-Requested-With,Content-Type,Accept,content-type,application/json');
    next();
});

// Middlewares
app.use(bodyParser.json());

// Routes
app.use('/auth', authRoute);
app.use('/user', userRoute);
app.use('/chat', chatRoute);

app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

module.exports = app;