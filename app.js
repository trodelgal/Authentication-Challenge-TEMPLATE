const express = require('express');
const app = express();
const morgan = require('morgan');
const checkToken = require('./middleware/auth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const USERS = [{ email: "admin@email.com",
    name: "admin",
    password: "$2b$10$t6NWpSU.Z9InTgo6stZf7eIivLA6hZ5WlsFV3eKrNL2h.3RsOh0Oi",
    isAdmin: true }];
const INFORMATION = [{user:"admin", info:"admin info"}];
const REFRESH_TOKENS = [];

app.use(express.json());



bcrypt.hash("Rc123456!", 10).then(res=>{
    // console.log(res);
});

app.post("/users/register", async (req,res)=>{
    const { name, email, password } = req.body;
    let hashPass = '';
    USERS.forEach(value => {
        if (value.email === email){
            return res.status(409).json("user already exists")
        }
    })
    await bcrypt.hash( password, 10).then(res=>{
        hashPass = res
    })
    USERS.push({
        name: name,
        email: email,
        password: hashPass,
    })
    INFORMATION.push({name: name,
        info:`${name} info`
    })
    console.log("register");
    res.status(201).json({message:"Register Success"})
})

app.post("/users/login", async (req,res)=>{
    const { email ,password } = req.body;
    let exist = USERS.findIndex(value => value.email === email)
    if(exist === -1){
        return res.status(404).json("cannot find user") 
    }else{
        userLogin = USERS[exist];
        let comparePass = await bcrypt.compare(password, userLogin.password)
        if(comparePass){
            const accessToken = jwt.sign({name: userLogin.name },
                'secret',
                {
                    expiresIn: '30s',
                });
            const refreshToken = jwt.sign({name: userLogin.name  },
                'secret',
                {
                    expiresIn: '24h',  
                });
                REFRESH_TOKENS.push(refreshToken);
            res.status(200).json({accessToken, refreshToken , userName: userLogin.name, isAdmin: userLogin.isAdmin})
        }else{
            res.status(403).json("User or Password incorrect") 
        }
    }
    
})

app.post("/users/logout", async (req, res)=>{
    if(!req.body.token){
        res.status(400).json("Refresh Token Required")
    }
    const index = REFRESH_TOKENS.findIndex(value => value === req.body.token);
    if(index === -1){
        res.status(403).json("Invalid Refresh Token")
    }else{
        REFRESH_TOKENS.splice(index,1);
        res.status(200).json({message: "User Logged Out Successfully"})
    } 
})

app.post("/users/tokenValidate", checkToken ,(req,res)=>{
    res.status(200).json({valid: true});
})
app.post("/users/token", async (req,res)=>{
    const {token} = req.body;
    if(!token){
        res.status(401).json("Refresh Token Required")
    }else{
        jwt.verify(token, 'secret', (err, decoded) => {
            if (err) {
              return res.status(403).json("Invalid Refresh Token");
            }
            const accessToken = jwt.sign({name: decoded.name},
                'secret',
                {
                    expiresIn: '30s',
                });
            res.status(200).json({accessToken})
          });
    }
} )

app.get("/api/v1/information", checkToken, async (req,res)=>{
    console.log(req.decoded);
    const info = INFORMATION.filter(user => user.user === req.decoded.name)
    console.log("info", info);
    res.status(200).json(info.map(user=>{
        return {
            user: user.name,
            info: user.info
        }
    }))
})

app.get("/api/v1/users",checkToken, (req,res)=>{
    const user = USERS.filter(user => user.name === req.decoded.name);
    if(user[0].isAdmin){
        res.status(200).json(USERS)
    }else{
        res.status(400).send('User is not admin')
    }
})

// const errorHandler = (error, request, response, next) => {
//     console.error(error.message)
//     if (error.name === 'CastError') {
//       return response.status(400).send({ error: 'malformatted id' })
//     } 
//     next(error)
//   } 
//   app.use(errorHandler)
  
  const unknownEndpoint = (request, response) => {
    response.status(404).send({ error: 'unknown endpoint' })
  }
  app.use(unknownEndpoint)
  


module.exports = app;