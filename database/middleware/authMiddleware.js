const asyncHandler = require('express-async-handler')
// const User = require('../models/userModel')
const Hospital = require('../models/hospitalsModel')
const Doctor = require('../models/doctorsModel')
const jwt = require('jsonwebtoken')
const Patient = require('../models/patientsModel')



function generateRandomString() {
      const numbers = '0123456789';
      const specialChars = '@#$%';
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      const allChars = numbers + specialChars + alphabet;
      let result = '';
    
      // Generate 8 random numbers
      for (let i = 0; i < 8; i++) {
        const randomIndex = Math.floor(Math.random() * numbers.length);
        result += numbers[randomIndex];
      }
    
      // Generate 2 random special characters
      for (let i = 0; i < 2; i++) {
        const randomIndex = Math.floor(Math.random() * specialChars.length);
        result += specialChars[randomIndex];
      }
    
      // Generate 2 random alphabet characters
      for (let i = 0; i < 2; i++) {
        const randomIndex = Math.floor(Math.random() * alphabet.length);
        result += alphabet[randomIndex];
      }
    
      // Shuffle the result string to arrange characters randomly
      result = result.split('');
      for (let i = result.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [result[i], result[j]] = [result[j], result[i]];
      }
    
      return result.join('');
}
    
    
 


const hospitalProtect = asyncHandler(async (req, res, next) => {
      try {
            const token = req.cookies.token
            if(!token){
                  res.status(401)
                  throw new Error('not authorized')
            }

            // verify token
            const verified = jwt.verify(token, process.env.JWT_SECRET)
            // get user id from token
            const hospital = await Hospital.findById(verified.id).select('-password')

            if(!hospital){
                  res.status(404)
                  throw new Error('user not found')
            }

            if(hospital.role === 'suspended'){
                  res.status(400)
                  throw new Error('hospital suspended, pls contact support')
            }

            req.hospital = hospital
            next()

      } catch (error) {
            res.status(401)
            throw new Error('not authorized')
      }
})
const doctorProtect = asyncHandler(async (req, res, next) => {
      try {
            const token = req.cookies.token
            if(!token){
                  res.status(401)
                  throw new Error('not authorized')
            }

            // verify token
            const verified = jwt.verify(token, process.env.JWT_SECRET)
            // get user id from token
            const doctor = await Doctor.findById(verified.id).select('-password')

            if(!doctor){
                  res.status(404)
                  throw new Error('user not found')
            }

            if(doctor.role === 'suspended'){
                  res.status(400)
                  throw new Error('user suspended, pls contact support')
            }

            req.doctor = doctor
            next()

      } catch (error) {
            res.status(401)
            throw new Error('not authorized')
      }
})
const patientProtect = asyncHandler(async (req, res, next) => {
      try {
            const token = req.cookies.token
            if(!token){
                  res.status(401)
                  throw new Error('not authorized')
            }

            // verify token
            const verified = jwt.verify(token, process.env.JWT_SECRET)
            // get user id from token
            const patient = await Patient.findById(verified.id).select('-password')

            if(!patient){
                  res.status(404)
                  throw new Error('user not found')
            }

            if(patient.role === 'suspended'){
                  res.status(400)
                  throw new Error('user suspended, pls contact support')
            }

            req.patient = patient
            next()

      } catch (error) {
            res.status(401)
            throw new Error('not authorized')
      }
})


const patientAdminOnly = asyncHandler( async (req, res, next) => {
      if (req.patient && req.patient.role === 'admin'){
            next()
      }else{
            res.status(401)
            throw new Error('Not authorized as an admin')
      }
})
const doctorAdminOnly = asyncHandler( async (req, res, next) => {
      if (req.doctor && req.doctor.role === 'admin'){
            next()
      }else{
            res.status(401)
            throw new Error('Not authorized as an admin')
      }
})
const hospitalAdminOnly = asyncHandler( async (req, res, next) => {
      if (req.hospital && req.hospital.role === 'admin'){
            next()
      }else{
            res.status(401)
            throw new Error('Not authorized as an admin')
      }
})
const authorOnly = asyncHandler (async (req, res, next) => {
      if (req.user && req.user.role === 'author' || req.user.role === 'admin'){
            next()
      }else{
            res.status(401)
            throw new Error('Not authorized as an author')
      }
})

const verifiedOnly = asyncHandler( async (req, res, next) => {
      if (req.user && req.user.isVerified ){
            next()
      }else{
            res.status(401)
            throw new Error('Not authorized... not verified')
      }
}
)
module.exports = {
      authorOnly,
      verifiedOnly,
      generateRandomString,
      hospitalProtect,
      hospitalAdminOnly,
      doctorAdminOnly,
      doctorProtect,
      patientAdminOnly,
      patientProtect

}