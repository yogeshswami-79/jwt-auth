require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const logger = require('./utils/Logger');
const requestsLogger = require("./middlewares/ReqLogger");

const app = express();
const PORT = process.env.PORT;

if(!PORT) throw "NO PORT DEFINED";

const users = []
let refreshTokens = []

// middlewares
app.use( bodyParser.urlencoded( { extended: true } ) );
app.use( bodyParser.json() )
app.use( requestsLogger );


// Register User
app.post('/users/register', async(req,res)=>{
    if(!hasEnoughInfo(req)) return res.sendStatus(406);
    
    if(userAlreadyExists(req)) return res.status(403).send("User Already Exists");

    try{
        const u = getHashedUser(extractUserInfoFromReq(req))
        users.push(u)
        res.status(201).send(`User Registered`)
        logger.info("User Registered ", { username: u.username, email: u.email } );
     }
     catch(e){  
        logger.error(e.message);
        res.status(500).send("Failed")
     }
})


// Login User
app.post('/users/login', (req,res)=>{
    const user = users.find(user => user.name == req.body.name )

    if(!user) return res.status(400).send("User doesn't Exists");

    try{
        
        if((compareHash(req.body.password, user.salt, user.hash)))
        {
            return res.json(getTokens(user.email))
        }

        return res.status(404).json({err:"Wrong Password"})
    }

    catch(e){
        res.status(500).send()
    }
})


// Generate Access Token
app.post('/token', (req, res)=>{
    const authHeader = req.headers['authorization']
    const refreshToken = authHeader && authHeader.split(' ')[1]

    if( refreshToken && !tokenExists(refreshToken) ) return res.sendStatus(401)

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(401)
        
        return res.json(getAccessToken(user.email))
    })

})


// Logout 
app.delete('/logout', (req,res)=>{
    const tkn = req.body.token;
    if(!tkn) return res.sendStatus(401)

    refreshTokens = refreshTokens.filter(token => token != tkn);
    res.sendStatus(204);
})


// Get User
app.get('/data', authenticateToken, (req,res)=>{
    const u = users.find(user => user.email === req.user.email);
    const { hash , salt, ...data } = u;
    res.send( data );
})


// Does user exists
function userExists(email){
    const usr = users.find(u => u.email === email) 
    return usr != null
}


// user data with hash 
function getHashedUser (user){
    const salt = crypto.randomBytes(16).toString('hex')
    const hash = crypto.pbkdf2Sync(user.password, salt, 10000, 512, 'sha512').toString('hex');

    const u = {
        name:user.name,
        username:user.username,
        email:user.email,
        salt:salt,
        hash:hash
    }
    return u
}


function compareHash(password, salt, validHash){
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 512, 'sha512').toString('hex');
    return hash===validHash;

}


function extractUserInfoFromReq(req){               
    const u = {
        name:req.body.name,
        username:req.body.username,
        email:req.body.email, 
        password:req.body.password,
    }
    return u
}

// get new Access tokens
function getTokens( email ) {
    const user = { email:email };
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '30s'})
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
    refreshTokens.push(refreshToken);
    return {accessToken:accessToken, refreshToken:refreshToken};
}

// get Access and refresh tokens
function getAccessToken(email){
    const user = { email:email };
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '30s'})
    return { accessToken:accessToken };
}


// Verify Access Token
function authenticateToken( req, res, next ) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(!token) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user)=>{
        if(err) return res.sendStatus(403)
        if(! userExists(user.email) ) return res.sendStatus(403)
        req.user = user;
        next();
    })
}

function hasEnoughInfo(req){
    return (req.body.username && req.body.email && req.body.password)
}

function userAlreadyExists(req){
    const u = users.find(user => user.username === req.body.username || user.email === req.body.email)
    return u != null;
}

function tokenExists(token){
    const t = refreshTokens.find(tkn => tkn === token)
    return t != null
}

app.listen(PORT,()=>console.log(`server started on port: ${PORT}`))
