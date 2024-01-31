require('dotenv').config();
const express = require('express') 
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express()

const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@jwt.dzsk4ik.mongodb.net/?retryWrites=true&w=majority`).then(()=>{
app.listen(3000, () => console.log('Listening on port 3000'))
}).catch((err) => console.log(err))

app.use(express.json())


//Models
const User = require('./models/User')

//PUBLIC ROUTE
app.get('/', (req,res) =>{
    console.log(req)
    res.status(200).send('sussesfull')
})

//REGISTER ROUTE

app.post('/auth/register',async (req,res)=>{

    const {name,email,password,confirmPassword}= req.body;

    if(!name || !email || !password || !confirmPassword){
        return res.status(422).json({msg : 'Invalid Fields'})
    }
    if(password !=confirmPassword){
        return res.status(422).json({msg : 'ConfirmPassowrd is not equal to Password'})

    }
    //check if user existis

    const userExists = await User.findOne({email : email})
    if(userExists){
        return res.status(422).json({msg : 'User already exists'})
    }

    //hash security password savement
    const salt = await bcrypt.genSalt(12)
    const HashPassword = await bcrypt.hash(password,salt)

    //creating new User
    const user = new User({
        name,
        email,
        password : HashPassword
    })
    //salva usuario no banco de dados
  try{
    await user.save();
    res.status(201).json({msg : 'User created successfully'})
  } catch(err){
    console.log(err)
  }
//cria token de autenticação para retornar ao cliente


})


app.post('/auth/login',async (req,res)=>{

    //email and password exists
    const {email,password} =await req.body
    if(!email || !password)return res.status(422).json({msg : 'Invalid Fields'});
    //user exists
    const UserExists =await User.findOne({email : email})
    if(!UserExists) return res.status(422).json({msg : 'User not found'});
    //password is correct
    const hash = bcrypt.compare(password,UserExists.password)
    if(!hash) return res.status(422).json({msg : 'Invalid Password'});

    //tudo certo, criar token de permissão para usuario
    try{
const secret =await process.env.SECRET;
console.log(secret)
const token =await jwt.sign({
    sub : UserExists._id
},secret)

return res.status(200).json({msg : 'Succesful Login',token})
    }catch(err){
        console.log(err)
       return res.status(422).json({msg : 'Has Occurred and Error in the server'})
    }
    return res.status(200).json({msg : 'Succesful Login'})
})
function verifyJWT(req,res,next){
    const header = req.headers['authorization']
    const token = header.split(' ')[1]
    if(!token) return res.status(401).json({msg : 'Access Denied no token'})
    try{
        const secret = process.env.SECRET
        jwt.verify(token,secret)
        next()  
    }catch(err){
        return res.status(401).json({msg : 'Access Denied invalid',token})
    }
}
app.get('/user/:id',verifyJWT,async (req,res)=>{
    //pega o id do parametro
    const id = req.params.id
    //resgata o usuario pelo id mas retira o valor da senha
    const user = await User.findById(id,'-password')
    //validação se o usuario existe
    if(!user) return res.status(404).json({msg : 'User not found'})
    return res.status(200).json(user)
})
