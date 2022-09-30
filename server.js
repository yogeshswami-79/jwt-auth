const express = require("express");
const DB = require("./utils/Database")
const bodyParser = require("body-parser");
const authRoute = require("./Routes/Auth/Auth");
require('dotenv').config()


// Server Instance
const app = express();
const PORT = process.env.PORT || 3002;


// Connect to DB and Start Server on Defined Port
DB.initDB(process.env.DB_URL)
.then(()=>{
    console.log('Connected To DB')
    app.listen(PORT, ()=>console.log(`Server started on PORT : ${PORT}`)) 
})
.catch(e => console.log(`error :\n${e}`))


// presets
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/', (req,res)=>{
    DB
    .getUser( "" , "wecode" , "yogeshswami79@gmail.com" )
    .then( user => res.send(user) )
    .catch( e => console.log(e) )
})
// Auth routes
app.use("/auth", authRoute);


