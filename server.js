require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const requestsLogger = require("./middlewares/logger/ReqLogger");
const authorizeRequest = require("./middlewares/auth/Auth");
const authRoute = require("./routes/auth/Auth");
const { users } = require('./utils/Cache');

const app = express();
const PORT = process.env.PORT;

if( !PORT ) throw "NO PORT DEFINED";

// middlewares
app.use( bodyParser.urlencoded( { extended: true } ) );
app.use( bodyParser.json() )
app.use( requestsLogger );
app.use( '/users' , authRoute );

// Get User
app.get('/data', authorizeRequest, (req,res)=>{
    const u = users.find(user => user.email === req.user.email);
    const { hash , salt, ...data } = u;
    res.send( data );
})


app.listen(PORT,()=>console.log(`server started on port: ${PORT}`))
