const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const fs = require("fs")
const bcrypt = require("bcrypt")

const users = require("./users")

const app = express()

app.use(bodyParser.json())

const privateKey = fs.readFileSync("private.key")
const publicKey = fs.readFileSync("public.key")

// LOGIN
app.post("/login", async (req,res)=>{

const {username,password} = req.body

const user = users.find(u=>u.username===username)

if(!user){
return res.status(401).json({message:"User not found"})
}

const match = await bcrypt.compare(password,user.password)

if(!match){
return res.status(401).json({message:"Wrong password"})
}

const token = jwt.sign(
{
id:user.id,
username:user.username
},
privateKey,
{
algorithm:"RS256",
expiresIn:"1h"
}
)

res.json({token})

})


// middleware kiểm tra token
function authMiddleware(req,res,next){

const authHeader = req.headers.authorization

if(!authHeader){
return res.status(401).json({message:"No token"})
}

const token = authHeader.split(" ")[1]

jwt.verify(token,publicKey,{algorithms:["RS256"]},(err,decoded)=>{

if(err){
return res.status(401).json({message:"Invalid token"})
}

req.user = decoded
next()

})

}


// /me
app.get("/me",authMiddleware,(req,res)=>{

res.json({
user:req.user
})

})


// change password
app.post("/changepassword",authMiddleware,async(req,res)=>{

const {oldPassword,newPassword} = req.body

if(!oldPassword || !newPassword){
return res.status(400).json({message:"Missing password"})
}

if(newPassword.length < 6){
return res.status(400).json({
message:"New password must be at least 6 characters"
})
}

const user = users.find(u=>u.id===req.user.id)

const match = await bcrypt.compare(oldPassword,user.password)

if(!match){
return res.status(400).json({message:"Old password incorrect"})
}

const hashed = await bcrypt.hash(newPassword,10)

user.password = hashed

res.json({
message:"Password changed successfully"
})

})


app.listen(3000,()=>{
console.log("Server running on port 3000")
})