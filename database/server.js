require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const patientRoute = require('./routes/patientRoute')
const doctorRoute = require('./routes/doctorRoute')
const hospitalRoute = require('./routes/hospitalRoute')
const errorHandler = require('./middleware/errorMiddleWare')



const app = express()

app.use(express.json())
app.use(express.urlencoded({extended: false}))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(
      cors({
            origin:['http://localhost:5173', 'https://authTest.vercel.app'],
            credentials:true,
      })
)
//ROutes

app.use('/api/patients', patientRoute)
app.use('/api/hospitals', hospitalRoute)
app.use('/api/doctors', doctorRoute)

app.get('/', (req, res) =>{ 
      res.send('Home Page')
 });

 //Error Handler

 app.use(errorHandler);

 const PORT =  process.env.PORT || 5000

 mongoose.connect(process.env.MONGO_URI).then(() => {
      app.listen(PORT, () => {
            console.log(`server running on ${PORT}`)
      })
 }) .catch((err) => console.log(err))

