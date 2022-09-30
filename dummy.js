const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
require('dotenv').config()


const PORT = 3002;
const app = express();

app.use(bodyParser.json())
let data = ["data", "a",123,1234,12345,1234567]



app.get('/data', authenticateToken, (req,res)=>{
    res.json(data)
})


function getAccessToken(name){
    const u = {name:name};
    const accessToken = jwt.sign(u, process.env.ACCESS_TOKEN_SECRET)
    return {accessToken:accessToken};
}

function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(!token) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user)=>{
        if(err) return res.sendStatus(403)

        req.user = user;
        next();
    })
}

app.listen(PORT,()=>console.log(`server started`))
























