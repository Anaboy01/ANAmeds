const asyncHandler = require('express-async-handler')
const bcrypt = require('bcryptjs')
const { generateToken, hashToken } = require('../utils');
const parser = require('ua-parser-js')
const jwt = require('jsonwebtoken')
const sendEmail = require('../utils/sendEmail')
const crypto = require('crypto')
const Cryptr = require('cryptr')
const nodemailer = require("nodemailer");
const hbs = require("nodemailer-express-handlebars");
const path = require('path');
const Doctor = require('../models/doctorsModel')
const Token = require('../models/tokenModel');
const Hospital = require('../models/hospitalsModel')

const cryptr = new Cryptr(process.env.CRYPTR_KEY)


const registerDoctor = asyncHandler(async (req, res) => {
      const { name, password, email, phone, specialty, licenseNumber, rank } = req.body;
    
      // Validation
      if (!name || !email || !password) {
        res.status(400).json({ error: 'Please fill in all the required fields' });
        return;
      }
    
      if (password.length < 6) {
        res.status(400).json({ error: 'Password must be at least 6 characters long' });
        return;
      }
    
      try {
        // Assuming you have a way to authenticate and identify the requesting hospital (e.g., through req.user)
        const hospitalId = req.hospital._id;
    
        // Check if the hospital exists (optional, you can skip this check if you trust the provided hospitalId)
        const hospital = await Hospital.findById(hospitalId);
    
        if (!hospital) {
          res.status(404).json({ error: 'Hospital not found' });
          return;
        }
    
        // Check if the email is already in use by a doctor
        const doctorExists = await Doctor.findOne({ 'contactInfo.email': email });
    
        if (doctorExists) {
          res.status(400).json({ error: 'Email already in use' });
          return;
        }
    
        // Get user agent
        const ua = parser(req.headers['user-agent']);
        const doctorAgent = ua.ua;
    
        // Hash the password
    
        // Create a new hospital user
        const doctor = await Doctor.create({
          name,
          password,
          contactInfo: {
            email: email,
            phone: phone,
          },
          doctorAgent,
          specialty,
          licenseNumber,
          hospitalId, // Set the hospitalId using the authenticated hospital's ID
          rank
        });
    
        // Generate Token
        const token = generateToken(doctor._id);
    
        // Send HTTP-only cookie
        res.cookie('token', token, {
          path: '/',
          httpOnly: true,
          expires: new Date(Date.now() + 1000 * 86400), // 1 day
          sameSite: 'none',
          secure: true,
        });
    
        // Return the doctor data in the response
        res.status(201).json({
          _id: doctor._id,
          name: doctor.name,
          contactInfo: doctor.contactInfo,
          specialty,
          licenseNumber,
          hospitalId,
          rank
          // Add other properties you want to return here
        });
      } catch (error) {
        console.error('Error registering doctor:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
    

const loginDoctor = asyncHandler (async (req, res) => {
      const {email, password} = req.body
      //validation
    
      if (!email || !password){
            res.status(400);
            throw new Error('pls fill in all the required fields')
      }
    
      const doctor = await Doctor.findOne({'contactInfo.email': email});
    
      if (!doctor){
            res.status(404);
            throw new Error('user not found... pls sign up')
      }
    
      const passwordIsCorrect = await bcrypt.compare(password, doctor.password)
    
      if (!passwordIsCorrect){
            res.status(400);
            throw new Error('Invalid email or password')
      }
    
      // Trigger 2fa for unknown userAgent
    
      const ua = parser(req.headers['user-agent']);
      const thisDoctorAgent = ua.ua
    
      console.log(thisDoctorAgent)
      const allowedAgent = doctor.doctorAgent.includes(thisDoctorAgent)
    
      if (!allowedAgent){
    
            // Generate 6 digit random code
            const loginCode = Math.floor(100000 + Math.random() * 900000)
    
            console.log(loginCode)
    
    
            // Encrypt login code before saving to database
    
            const encryptedLoginCode = cryptr.encrypt(loginCode.toString())
    
                  // Delete token if it exists in DB
                  let doctorToken = await Token.findOne({ doctorId: doctor._id });
                  if (doctorToken) {
                  await doctorToken.deleteOne();
                  }
      
            // Save Token to DB
            await new Token({
            doctorId: doctor._id,
            lToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
            }).save();
    
            res.status(400)
            throw new Error('New browser or device detected')
    
    
     
    
      }
    
      const token = generateToken(doctor._id)
    
      if(doctor && passwordIsCorrect){
            res.cookie('token', token,{
                  path:'/',
                  httpOnly: true,
                  expires: new Date(Date.now() + 1000 * 86400), // 1 day
                  sameSite: 'none',
                  secure: true,
            })
    
            const {  _id,
                  name,
                  password,
                  contactInfo,
                  doctorAgent,
                  specialty,
                  licenseNumber,
                  hospitalId,role} = doctor
    
            res.status(200).json({
                  _id,
                  hospitalId,
                  name,
                  password,
                  contactInfo,
                  doctorAgent,
                  specialty,
                  licenseNumber,
                  role
            })
    
      } else{
            res.status(500)
            throw new Error('something went wrong')
      }
    
    
    
    
    
})

const loginWithCode = asyncHandler(async (req, res) => {
      const {email} = req.params
      const {loginCode} = req.body
    
    
      const doctor = await Doctor.findOne({'contactInfo.email': email});
    
    
      if(!doctor){
            res.status(404);
            throw new Error('User not found')
      }
    
      // Find user login token
    
      const doctorToken = await Token.findOne({
            doctorId: doctor.id,
            expiresAt: { $gt: Date.now()},
      })
    
      if (!doctorToken){
            res.status(404)
            throw new Error('Invalid token, pls log in again')
      }
    
      const decryptedLoginCode = cryptr.decrypt(doctorToken.lToken);
    
      if (loginCode !== decryptedLoginCode) {
    
            res.status(400)
            throw new Error('incorrect login code')
            
      } else {
            //    Register user agent
    
            const ua = parser(req.headers['user-agent'])
            const thisDoctorAgent = ua.ua;
    
            doctor.doctorAgent.push(thisDoctorAgent)
    
            await doctor.save()
    
            const token = generateToken(doctor._id)
    
    
    // Send HTTP-only cookie
    
      res.cookie('token', token,{
            path:'/',
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: 'none',
            secure: true,
      })
    
      
      const {  _id,
            name,
            password,
            contactInfo,
            doctorAgent,
            specialty,
            licenseNumber,
            hospitalId} = doctor

      res.status(200).json({
            _id,
            hospitalId,
            name,
            password,
            contactInfo,
            doctorAgent,
            specialty,
            licenseNumber,
      })
    
      }
    })

const logoutDoctor = asyncHandler (async (req, res)=> { 
      res.cookie('token', '',{
            path:'/',
            httpOnly: true,
            expires: new Date(0), // 1 day
            sameSite: 'none',
            secure: true,
      });
      return res.status(200).json ({message: 'Logout successful'})
})

const loginStatus = asyncHandler(async (req, res) => {
      const token = req.cookies.token
      if (!token){
            return res.json(false)
      }

      //Verify token

      const verified = jwt.verify(token, process.env.JWT_SECRET)

      if(verified) {
            return res.json(true)
      }

      return res.json(false)
    })


const getDoctor = asyncHandler (async (req, res) => {
      const doctor = await Doctor.findById(req.doctor._id)
    
      if (doctor){
    
           
            const {  _id,
                  name,
                  password,
                  contactInfo,
                  doctorAgent,
                  specialty,
                  licenseNumber,
                  hospitalId,
                  role} = doctor
    
            res.status(200).json({
                  _id,
                  hospitalId,
                  name,
                  password,
                  contactInfo,
                  doctorAgent,
                  specialty,
                  licenseNumber,
                  role
            })
    
      }else{
            res.status(404)
            throw new Error('user not found')
      }
    })

const getAllDoctors = asyncHandler(async (req, res) => {
      const doctors = await Doctor.find().sort('-createdAt').select('-password')
    
      if(!doctors){
            res.status(500)
            throw new Error('Something went wrong')
      }
      res.status(200).json(doctors)
    })


const getDoctorsByHospitalId = asyncHandler(async (req, res) => {

      const hospitalId = req.hospital._id; // Assuming hospitalId is stored in the authenticated hospital's data

      try {
        // Find the hospital by its ID
        const hospital = await Hospital.findById(hospitalId);
    
        if (!hospital) {
          return res.status(404).json({ message: 'Hospital not found' });
        }
    
        // Query the database to find all doctors with the specified hospitalId
        const doctors = await Doctor.find({ hospitalId });
    
        if (!doctors || doctors.length === 0) {
          return res.status(404).json({ message: 'No doctors found for the requesting hospital' });
        }
    
        // Return the list of doctors in the response
        res.status(200).json(doctors);
      } catch (error) {
        console.error('Error getting doctors by hospitalId:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
 });

const getDoctorByEmailAndHospitalId = asyncHandler(async (req, res) => {
      const { email } = req.body;
      const hospitalId = req.hospital._id;

      if(!email){
            res.status(400).json({ error: 'Please fill in all the required fields' });
      }
    
      try {
        // Query the database to find a doctor with the specified email and hospitalId
        const doctor = await Doctor.findOne({ 'contactInfo.email': email, hospitalId });
    
        if (!doctor) {
          return res.status(404).json({ message: 'Doctor not found for the specified hospital and email' });
        }
    
        // Return the doctor in the response
        res.status(200).json(doctor);
      } catch (error) {
        console.error('Error getting doctor by email and hospitalId:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

const updateDoctor = asyncHandler(async (req, res) => {
      try {
        const doctor = await Doctor.findById(req.doctor._id);
    
        if (doctor) {
          doctor.name = req.body.name || doctor.name;
    
          doctor.contactInfo.phone = req.body.phone || doctor.contactInfo.phone;
    
          doctor.specialty = req.body.specialty || doctor.specialty;
    
          doctor.licenseNumber.website = req.body.licenseNumber || doctor.licenseNumber ;

          const updatedDoctor = await doctor.save();
          res.status(200).json(updatedDoctor);
        } else {
          res.status(404).json({ error: "User not found" });
        }
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

const deleteDoctor = asyncHandler(async (req, res) => {
      try {
        const doctor = await Doctor.findById(req.params.id);
    
        if (!doctor) {
          return res.status(404).json({ message: 'Doctor not found' });
        }


    
        // Check if the doctor's hospitalId matches the requesting hospital's id
        if (doctor.hospitalId.toString() !== req.hospital._id.toString()) {
          return res.status(403).json({ message: 'Permission denied. This doctor does not belong to your hospital' });
        }
    
        // Perform the deletion
        await doctor.deleteOne();
    
        res.status(200).json({ message: 'Doctor deleted successfully' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
      }
 });

 const changeDoctorStatus = asyncHandler(async (req, res) => {
      const { doctorId } = req.params;
      const { rank, isVerified } = req.body;
    
      // Find the doctor by their ID
      const doctor = await Doctor.findById(doctorId);
    
      if (!doctor) {
        return res.status(404).json({ message: 'Doctor not found' });
      }
    
      // Check if the hospital with the specified hospitalId exists
      const hospitalExists = await Hospital.exists({ _id: doctor.hospitalId });
    
      if (!hospitalExists) {
        return res.status(404).json({ message: 'Hospital not found for this doctor' });
      }
    
      // Check if the hospitalId matches the request hospital's _id
      if (doctor.hospitalId.toString() !== req.hospital._id.toString()) {
        return res.status(403).json({ message: 'Access denied: Doctor does not belong to this hospital' });
      }
    
      // Update the rank and isVerified fields if the respective values are provided
      if (rank) {
        doctor.rank = req.body.rank || doctor.rank;
      }
    
      if (typeof isVerified === 'boolean') {
        doctor.isVerified = isVerified;
      }
    
      // Save the updated doctor
      await doctor.save();
    
      // Return the updated doctor data
      res.status(200).json({ message: 'Doctor updated successfully', doctor });
    });

const sendLoginCode = asyncHandler(async (req, res) => {
      const {email} = req.params
      const doctor = await Doctor.findOne({'contactInfo.email': email});
    
    
      if(!doctor){
            res.status(404)
            throw new Error('User not found')
      }
    
      // Find Login Code in DB
      let doctorToken = await Token.findOne({ doctorId: doctor._id,
      expiresAt: {$gt: Date.now()}
      });
      if(!doctorToken){
            res.status(404)
            throw new Error('Invalid or Expired token, please login again')
      }
    
      const loginCode = doctorToken.lToken;
    
      const decryptedLoginCode = cryptr.decrypt(loginCode);
    
      //Send Login Code
    
      const subject = "Login Access Code - AUTH:Z";
       const send_to = doctor.contactInfo.email;
       const sent_from = process.env.EMAIL_USER;
       const reply_to = "noreply@zinotrustacademy.com";
       const template = "loginCode";
       const name = doctor.name;
       const link = decryptedLoginCode;
     
       try {
         await sendEmail(
           subject,
           send_to,
           sent_from,
           reply_to,
           template,
           name,
           link
         );
         res.status(200).json({ success: true, message: `Access code sent to ${email}` });
       } catch (error) {
         res.status(500);
         throw new Error("Email not sent, please try again");
       }
    })

const forgotPassword = asyncHandler(async (req, res) => {
      const {email} = req.body
    
      const doctor = await Doctor.findOne({ 'contactInfo.email': email });
    
    
      if(!doctor){
            res.status(404)
            throw new Error('no user with this email')
      }
    
       // Delete token if it exists in DB
       let token = await Token.findOne({ doctorId: doctor._id });
       if (token) {
         await token.deleteOne();
       }
     
       // Create Verification Token and save
       const resetToken = crypto.randomBytes(32).toString("hex") + doctor.id;
    
       console.log(resetToken)
     
       // Hash token before saving to DB
       const hashedToken = hashToken(resetToken);
     
       // Save Token to DB
       await new Token({
         doctorId: doctor._id,
         rToken: hashedToken,
         createdAt: Date.now(),
         expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
       }).save();
     
       // Construct Reset Url
       const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;
     
      
       const subject = "Password Reset - AUTH:Z";
       const send_to = doctor.contactInfo.email;
       const sent_from = process.env.EMAIL_USER;
       const reply_to = "noreply@nigga.com";
       const template = "forgotPassword";
       const name = doctor.name;
       const link = resetUrl;
     
       try {
         await sendEmail(
           subject,
           send_to,
           sent_from,
           reply_to,
           template,
           name,
           link
         );
         res.status(200).json({ success: true, message: "Password Reset Email sent" });
       } catch (error) {
         res.status(500);
         throw new Error("Email not sent, please try again");
       }
    })
    
    const resetPassword = asyncHandler(async (req, res) => {
      const {resetToken} = req.params
      const {password} = req.body
    
      const hashedToken = hashToken(resetToken)
    
      const doctorToken = await Token.findOne({
            rToken: hashedToken,
            expiresAt: { $gt: Date.now()}
    
           
      })
    
      if(!doctorToken){
            res.status(404)
            throw new Error('invalid or expired token')
      }
    
      // FIND USER
    
      const doctor = await Doctor.findOne({_id: doctorToken.doctorId})
    
      // Now reset password
    
      doctor.password = password
      await doctor.save()
    
      res.status(200).json({message: 'Password Reset Sucessful, please login'})
    
    })
    
    const changePassword = asyncHandler(async (req, res) => {
      const {oldPassword, password} = req.body  
    const doctor = await Doctor.findById(req.doctor._id)
    
    if(!doctor){
        res.status(404)
        throw new Error('no user with this email')
    }
    
    if (!oldPassword || !password){
        res.status(400)
        throw new Error('pls enter old and new password');
        
    }
    
    const passwordIsCorrect = await bcrypt.compare(oldPassword, doctor.password)
    
    // Save new password
    
    if (doctor && passwordIsCorrect) {
    
      doctor.password = password
        await doctor.save()
    
        res.status(200).json({message: 'password change succesful, pls re login'})
        
    } else {
        res.status(400)
        throw new Error('old password incorrect')
    }
    })

    


    

    
    
    






module.exports = {
      registerDoctor,
      loginDoctor,
      sendLoginCode,
      logoutDoctor,
      loginStatus,
      getDoctor,
      getAllDoctors,
      getDoctorsByHospitalId,
      getDoctorByEmailAndHospitalId,
      updateDoctor,
      loginWithCode,
      deleteDoctor,
      changeDoctorStatus,
      resetPassword,
      changePassword,
      forgotPassword
    }