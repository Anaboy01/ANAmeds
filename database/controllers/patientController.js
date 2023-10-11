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
const Patient = require('../models/patientsModel')
// Async handler for adding a patient file to a patient's profile
const { v4: uuidv4 } = require('uuid'); // Import the UUID library

const generateAccessToken = (payload, expiresIn = '3h') => {
  // Replace 'your-secret-key' with your actual secret key
  const secretKey = 'your-secret-key';
  return jwt.sign(payload, secretKey, { expiresIn });
};

const cryptr = new Cryptr(process.env.CRYPTR_KEY)

const generateAccessCode = () => {
      // Generate a 6-digit random access code
      const min = 100000;
      const max = 999999;
      return Math.floor(Math.random() * (max - min + 1)) + min;
    }



//     Controllers

const registerPatient = asyncHandler(async (req, res) => {
      const {firstName, lastName, email, password} = req.body    
    
      //Validation
    
      if(!firstName || !lastName || !email || ! password){
          res.status(400)
          throw new Error('Please fill in all the required fields')
    
      }
      
      if(password.length < 6){
          throw new Error('Password must be up to 6 characters')
    }
    
    // Check if user exist 
    
    const patientExists = await Patient.findOne({ 'contactInfo.email': email })
    
    if (patientExists){
          res.status(400)
          throw new Error('Email already in use. ')
    }
    
    //Get  user agent
    
    const ua = parser(req.headers['user-agent']);
    const patientAgent = [ua.ua]
    
    // Create new user
    
    const patient = await Patient.create({
          name:{
            firstName: firstName,
            lastName: lastName
          },
          contactInfo:{ email: email},
          password,
          patientAgent
    })
    
    // Generate Token
    
    const token = generateToken(patient._id)
    
    
    // Send HTTP-only cookie
    
    res.cookie('token', token,{
          path:'/',
          httpOnly: true,
          expires: new Date(Date.now() + 1000 * 86400), // 1 day
          sameSite: 'none',
          secure: true,
    })
    
     if(patient) {
          const {_id, name, contactInfo, photo,role} = patient
    
          res.status(201).json({
            _id, name, contactInfo, photo,role
          })
     }else{
          res.status(400)
          throw new Error('invalid user data');
     }
    
    }) 

//SEND VERIFICATION eMAIL

const sendVerificationEmail = asyncHandler(async (req, res) => {
      const patient = await Patient.findById(req.patient._id);

     
    
      // Check if user doesn't exists
      if (!patient) {
        res.status(404);
        throw new Error("User not found");
      }
    
      if (patient.isVerified) {
        res.status(400);
        throw new Error("User already verified");
      }
    
      // Delete token if it exists in DB
      let token = await Token.findOne({ patientId: patient._id });
      if (token) {
        await token.deleteOne();
      }
    
      // Create Verification Token and save
      const verificationToken = crypto.randomBytes(32).toString("hex") + patient.id;

      console.log(verificationToken)
    
      // Hash token before saving to DB
      const hashedToken = hashToken(verificationToken);
    
      // Save Token to DB
      await new Token({
        patientId: patient._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
      }).save();
    
      // Construct Verification Url
      const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;
    
      // Verification Email
      // const message = `
      //     <h2>Hello ${user.name}</h2>
      //     <p>Please use the url below to verify your account</p>
      //     <p>This link is valid for 24hrs</p>
    
      //     <a href=${verificationUrl} clicktracking=off>${verificationUrl}</a>
    
      //     <p>Regards...</p>
      //     <p>AUTH:Z Team</p>
      //   `;

      const emailName = `${patient.name.firstName} ${patient.name.lastName}`;



      const subject = "Verify Your Account - AUTH:Z";
      const send_to = patient.contactInfo.email;
      const sent_from = process.env.EMAIL_USER;
      const reply_to = "noreply@zinotrustacademy.com";
      const template = "verifyEmail";
      const name = emailName;
      const link = verificationUrl;
    
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
        res.status(200).json({ success: true, message: "Verification Email Sent" });
      } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
      }
    });

const verifyPatient = asyncHandler(async (req, res) => {
      const {verificationToken} = req.params

      const hashedToken = hashToken(verificationToken)

      const patientToken = await Token.findOne({
            vToken: hashedToken,
            expiresAt: {$gt: Date.now()}

           
      })

      if(!patientToken){
            res.status(404)
            throw new Error('invalid pr expired token')
      }

      // FIND USER

      const patient = await Patient.findOne({_id: patientToken.patientId})

      if(patient.isVerified){
            res.status(400)
            throw new Error('user already verified')
      }

      patient.isVerified = true
      await patient.save()

      res.status(200).json({message: 'Account verification Sucessful'})

    })

// LOGIN CONTROLLER
const loginPatient = asyncHandler (async (req, res) => {
      const {email, password} = req.body
      //validation

      if (!email || !password){
            res.status(400);
            throw new Error('pls fill in all the required fields')
      }

       const patient = await Patient.findOne({'contactInfo.email': email});

      if (!patient){
            res.status(404);
            throw new Error('user not found... pls sign up')
      }

      const passwordIsCorrect = await bcrypt.compare(password, patient.password)

      if (!passwordIsCorrect){
            res.status(400);
            throw new Error('Invalid email or password')
      }

      // Trigger 2fa for unknown userAgent

      const ua = parser(req.headers['user-agent']);
      const thisPatientAgent = ua.ua

      console.log(thisPatientAgent)
      const allowedAgent = patient.patientAgent.includes(thisPatientAgent)

      if (!allowedAgent){

            // Generate 6 digit random code
            const loginCode = Math.floor(100000 + Math.random() * 900000)

            console.log(loginCode)


            // Encrypt login code before saving to database

            const encryptedLoginCode = cryptr.encrypt(loginCode.toString())

                  // Delete token if it exists in DB
            let patientToken = await Token.findOne({ patientId: patient._id });
            if (patientToken) {
            await patientToken.deleteOne();
            }
      
            // Save Token to DB
            await new Token({
            patientId: patient._id,
            lToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
            }).save();

            res.status(400)
            throw new Error('New browser or device detected')


     

      }

      const token = generateToken(patient._id)

      if(patient && passwordIsCorrect){
            res.cookie('token', token,{
                  path:'/',
                  httpOnly: true,
                  expires: new Date(Date.now() + 1000 * 86400), // 1 day
                  sameSite: 'none',
                  secure: true,
            })

            const {_id, name, contactInfo, role, photo, patient_file,  } = patient

            res.status(200).json({
                  _id, name, contactInfo, role, photo, patient_file,
            })

      } else{
            res.status(500)
            throw new Error('something went wrong')
      }





})

//SEND LOGIN CODE VIA EMAIL

const sendLoginCode = asyncHandler(async (req, res) => {
      const {email} = req.params
      const patient = await Patient.findOne({'contactInfo.email': email});
    
    
      if(!patient){
            res.status(404)
            throw new Error('User not found')
      }
    
      // Find Login Code in DB
      let patientToken = await Token.findOne({ patientId: patient._id,
      expiresAt: {$gt: Date.now()}
      });
      if(!patientToken){
            res.status(404)
            throw new Error('Invalid or Expired token, please login again')
      }
    
      const loginCode = patientToken.lToken;
    
      const decryptedLoginCode = cryptr.decrypt(loginCode);
    
      //Send Login Code

      const emailName = `${patient.name.firstName} ${patient.name.lastName}`;
    
      const subject = "Login Access Code - AUTH:Z";
       const send_to = patient.contactInfo.email;
       const sent_from = process.env.EMAIL_USER;
       const reply_to = "noreply@zinotrustacademy.com";
       const template = "loginCode";
       const name = emailName;
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

const loginWithCode = asyncHandler(async (req, res) => {
      const {email} = req.params
      const {loginCode} = req.body


      const patient = await Patient.findOne({'contactInfo.email': email});


      if(!patient){
            res.status(404);
            throw new Error('User not found')
      }

      // Find user login token

      const patientToken = await Token.findOne({
            patientId: patient.id,
            expiresAt: { $gt: Date.now()},
      })

      if (!patientToken){
            res.status(404)
            throw new Error('Invalid token, pls log in again')
      }

      const decryptedLoginCode = cryptr.decrypt(patientToken.lToken);

      if (loginCode !== decryptedLoginCode) {

            res.status(400)
            throw new Error('incorrect login code')
            
      } else {
            //    Register user agent

            const ua = parser(req.headers['user-agent'])
            const thisPatientAgent = ua.ua;

            patient.patientAgent.push(thisPatientAgent)

            await patient.save()

            const token = generateToken(patient._id)


// Send HTTP-only cookie

      res.cookie('token', token,{
            path:'/',
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: 'none',
            secure: true,
      })

      
      const {_id, name, contactInfo, role, photo, patient_file } = patient

      res.status(200).json({
            _id, name, contactInfo, role, photo, patient_file
      })

      }
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

    // LOGOUT CONTROLLER

const logoutPatient = asyncHandler (async (req, res)=> { 
      res.cookie('token', '',{
            path:'/',
            httpOnly: true,
            expires: new Date(0), // 1 day
            sameSite: 'none',
            secure: true,
      });
      return res.status(200).json ({message: 'Logout successful'})
})


const getPatient = asyncHandler(async (req, res) => {
 
  const patient = await Patient.findById(req.patient._id);

  if (patient) {
    const {
      _id,
      name,
      contactInfo,
      patientAgent,
      patient_files,
      photo,
      isVerified,
      role,
    } = patient;

    res.status(200).json({
      _id, // Use 'id' instead of '_id'
      name,
      contactInfo,
      patientAgent,
      patient_files,
      photo,
      isVerified,
      role
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});


const getAllPatients = asyncHandler(async (req, res) => {
      const patients = await Patient.find().sort('-createdAt').select('-password')
    
      if(!patients){
            res.status(500)
            throw new Error('Something went wrong')
      }
      res.status(200).json(patients)
    })


const updatePatient = asyncHandler(async (req, res) => {
      try {
        const patient = await Patient.findById(req.patient._id);
    
        if (patient) {

            patient.contactInfo.email = patient.contactInfo.email;
            
            patient.photo = req.body.photo || patient.photo;
    
            patient.contactInfo.phone = req.body.phone || patient.contactInfo.phone;
    
            patient.name.lastName = req.body.lastName || patient.name.lastName ;

            patient.name.firstName = req.body.firstName || patient.name.firstName ;

          const updatedPatient = await patient.save();
          res.status(200).json(updatedPatient);
        } else {
          res.status(404).json({ error: "User not found" });
        }
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

const deletePatient = asyncHandler(async (req, res) => {
      try {
        const patient = await Patient.findById(req.params.id);
    
        if (!patient) {
          return res.status(404).json({ message: 'patient not found' });
        }
    
        // Perform the deletion
        await patient.deleteOne();
    
        res.status(200).json({ message: 'Patient deleted successfully' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
      }
 });

// PASSWORD
const forgotPassword = asyncHandler(async (req, res) => {
      const {email} = req.body

       const patient = await Patient.findOne({'contactInfo.email': email});

      if(!patient){
            res.status(404)
            throw new Error('no patient with this email')
      }

       // Delete token if it exists in DB
       let token = await Token.findOne({ patientId: patient._id });
       if (token) {
         await token.deleteOne();
       }
     
       // Create Verification Token and save
       const resetToken = crypto.randomBytes(32).toString("hex") + patient.id;
 
       console.log(resetToken)
     
       // Hash token before saving to DB
       const hashedToken = hashToken(resetToken);
     
       // Save Token to DB
       await new Token({
         patientId: patient._id,
         rToken: hashedToken,
         createdAt: Date.now(),
         expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
       }).save();
     
       // Construct Reset Url
       const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;
     
      
       const subject = "Password Reset - AUTH:Z";
       const send_to = patient.contactInfo.email;
       const sent_from = process.env.EMAIL_USER;
       const reply_to = "noreply@zinotrustacademy.com";
       const template = "forgotPassword";
       const name = patient.name;
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

      const patientToken = await Token.findOne({
            rToken: hashedToken,
            expiresAt: { $gt: Date.now()}

           
      })

      if(!patientToken){
            res.status(404)
            throw new Error('invalid or expired token')
      }

      // FIND USER

      const patient = await Patient.findOne({_id: patientToken.patientId})

      // Now reset password

      patient.password = password
      await patient.save()

      res.status(200).json({message: 'Password Reset Sucessful, please login'})

   })

   const changePassword = asyncHandler(async (req, res) => {
          const {oldPassword, password} = req.body  
      const patient = await Patient.findById(req.patient._id)

      if(!patient){
            res.status(404)
            throw new Error('no patient with this email')
      }

      if (!oldPassword || !password){
            res.status(400)
            throw new Error('pls enter old and new password');
            
      }

      const passwordIsCorrect = await bcrypt.compare(oldPassword, patient.password)

      // Save new password

      if (patient && passwordIsCorrect) {

            patient.password = password
            await patient.save()

            res.status(200).json({message: 'password change succesful, pls re login'})
            
      } else {
            res.status(400)
            throw new Error('old password incorrect')
      }
   })

   const sendAccessCodeToPatient = async (patientEmail,patientName,accessCode) => {
      const subject = 'Access Code for Patient File Access - ANAMeds';
      const send_to = patientEmail; // Use the provided patient's email from the parameter
      const sent_from = process.env.EMAIL_USER;
      const reply_to = 'noreply@zinotrustacademy.com';
      const template = 'accessCode';
      const name = patientName; // Use the email as the name in this example
      const link = accessCode;
    
      try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
      } catch (error) {
        console.error('Email not sent:', error);
        throw new Error('Email not sent, please try again.');
      }
    };

const requestAccessToPatientData = asyncHandler(async (req, res) => {
      const patientEmail = req.body.email; // Retrieve patient's email from req.params
    
      // Check if the doctor is authorized to request patient data (you may have your own authorization logic)
    
      // Check if the patient with the provided email exists
      const patient = await Patient.findOne({ 'contactInfo.email': patientEmail});
    
      if (!patient) {
        res.status(404);
        throw new Error('Patient not found.');
      }
    
   // Generate a 6-digit access code
const accessCode = generateAccessCode();

// Encrypt the access code before saving it
const encryptedAccessCode = cryptr.encrypt(accessCode);

// Set the expiration time for the access code (3 hours from now)
const expirationTime = new Date();
expirationTime.setHours(expirationTime.getHours() + 3);

// Store the encrypted access code and its expiration timestamp in the patient's document
patient.accessCode = encryptedAccessCode;
patient.accessCodeTimestamp = expirationTime;
await patient.save();

      const lastName = patient.name.lastName
      const firstName = patient.name.firstName
    
      const patientName = `${lastName} ${firstName}`
      // Send the access code to the patient via email
      await sendAccessCodeToPatient(patientEmail,patientName, accessCode); // Call the function here
    
      res.status(200).json({ message: 'Access code sent to the patient successfully.' });
    });

 // Function to check if the access code has expired (1 hour expiration time)
 const isAccessCodeExpired = (timestamp) => {
      const currentTime = new Date();
      if (currentTime > new Date(timestamp)) {
        return 'Session expired. Please request a new access code.';
      } else {
        return null; // Access code is still valid
      }
    };
    
    
  


const accessPatientDataWithCode = asyncHandler(async (req, res) => {
   const { email } = req.params; // Retrieve patient's email from req.params
  const { accessCode } = req.body; // Retrieve access code from req.body

  // Find the patient by email
  const patient = await Patient.findOne({ 'contactInfo.email': email });

  if (!patient) {
    res.status(404);
    throw new Error('Patient not found.');
  }

  try {
   // Check if the provided access code matches the stored code and is not expired
      const decryptedAccessCode = cryptr.decrypt(patient.accessCode);

      if (
      decryptedAccessCode !== accessCode ||
      isAccessCodeExpired(patient.accessCodeTimestamp)
      ) {
      res.status(403);
      throw new Error('Invalid or expired access code.');
      }

    // Here you can return the patient's data or perform necessary actions
    const { _id, name, patient_files } = patient;

    // Delete the access code immediately after it's been used
    patient.accessCode = null;
    patient.accessCodeTimestamp = null;
    await patient.save();

    res.status(200).json({
      _id, name, patient_files
    });
  } catch (error) {
    res.status(403).json({ message: 'Invalid or expired access code.' });
  }
    });


    const addPatientFile = asyncHandler(async (req, res, next) => {
      try {
        // Get patient ID from request parameters
        const { email } = req.params;
    
        // Find the patient by email
        const patient = await Patient.findOne({ 'contactInfo.email': email });
    
        if (!patient) {
          return res.status(404).json({ error: 'Patient not found' });
        }
    
        // Get doctor details from the authenticated doctor in the request
        const { _id: doctorId, name: doctorName } = req.doctor;
    
        // Find the hospital associated with the doctor using their hospitalId
        const hospital = await Hospital.findById(req.doctor.hospitalId);
    
        if (!hospital) {
          return res.status(404).json({ error: 'Hospital not found' });
        }
    
        // Find the highest existing patient file ID and increment it
        let maxId = 0;
        patient.patient_files.forEach((file) => {
          if (file._id > maxId) {
            maxId = file._id;
          }
        });
    
        // Generate a new patient file ID by incrementing the maximum ID
        const newPatientFileId = maxId + 1;
    
        // Include the createdAt and updatedAt timestamps from your schema
        const currentTimestamp = Date.now(); // You may get the current timestamp
    
        // Create a new patient file with the doctor, hospital, and timestamps
        const newPatientFile = {
          _id: newPatientFileId,
          doctorId,
          doctorName,
          hospitalId: hospital._id,
          hospitalName: hospital.name,
          date: currentTimestamp, // You can set the date to the current timestamp
          createdAt: currentTimestamp, // Include createdAt timestamp
          updatedAt: currentTimestamp, // Include updatedAt timestamp
          ...req.body, // Assuming patientFileData is in the request body
        };
    
        // Add the new patient file to the patient's list of files
        patient.patient_files.push(newPatientFile);
    
        // Save the updated patient document
        await patient.save();
    
        return res.status(201).json(newPatientFile); // Return the newly created patient file
      } catch (error) {
        return next(error);
      }
    });
    
    
    
    


// Controller function to get patient files by email and hospitalId
const getPatientFilesByHospitalId = asyncHandler(async (req, res) => {
      const { email } = req.params; // Assuming you pass patient email and hospital ID as route parameters

      const hospitalId = req.hospital._id
    
      // Find the patient by their email
      const patient = await Patient.findOne({ 'contactInfo.email': email });
    
      // Check if the patient with the provided email exists
      if (!patient) {
        return res.status(404).json({ error: 'Patient not found for the provided email' });
      }
    
      // Filter patient_files based on the provided hospitalId
      const selectedFiles = patient.patient_files.filter((file) =>
        file.hospitalId.equals(hospitalId)
      );
    
      // Return the selected patient files
      res.json({ patientFiles: selectedFiles });
    });

    
const getPatientFilesByDoctorId = asyncHandler(async (req, res) => {
      const { email } = req.params; // Assuming you pass patient email and hospital ID as route parameters

      const doctorId = req.doctor._id
    
      // Find the patient by their email
      const patient = await Patient.findOne({ 'contactInfo.email': email });
    
      // Check if the patient with the provided email exists
      if (!patient) {
        return res.status(404).json({ error: 'Patient not found for the provided email' });
      }
    
      // Filter patient_files based on the provided hospitalId
      const selectedFiles = patient.patient_files.filter((file) =>
        file.doctorId.equals(doctorId)
      );
    
      // Return the selected patient files
      res.json({ patientFiles: selectedFiles });
    });


    const getPatientFileById = asyncHandler(async (req, res) => {
      const { email } = req.params; // Assuming you pass patient email and file ID as route parameters
      const { fileId } = req.body; // Assuming you pass patient email and file ID as route parameters
    
      // Find the patient by their email
      const patient = await Patient.findOne({ 'contactInfo.email': email });
    
      // Check if the patient with the provided email exists
      if (!patient) {
        return res.status(404).json({ error: 'Patient not found for the provided email' });
      }
    
      // Find the patient file by ID within the patient's files array
      const selectedFile = patient.patient_files.find((file) => file._id == fileId); // Using '==' for loose equality to handle different data types
    
      // Check if the file with the provided ID exists
      if (!selectedFile) {
        return res.status(404).json({ error: 'Patient file not found for the provided ID' });
      }
    
      // Fetch hospital and doctor information based on hospitalId and doctorId
      const hospital = await Hospital.findById(selectedFile.hospitalId);
      const doctor = await Doctor.findById(selectedFile.doctorId);
    
      // Check if hospital and doctor exist
      if (!hospital || !doctor) {
        return res.status(404).json({ error: 'Hospital or doctor not found' });
      }
    
      // Create a new object with the selected file data and include hospital and doctor names
      const responseFile = {
        ...selectedFile.toObject(), // Convert Mongoose document to plain JavaScript object
        hospitalName: hospital.name,
        doctorName: doctor.name,
      };
    
      // Return the modified file object
      res.json({ patientFile: responseFile });
    });
    
    
    
    
    

    
    





module.exports = {
     registerPatient,
     sendVerificationEmail,
     verifyPatient,
     loginPatient,
     sendLoginCode,
     loginWithCode,
     loginStatus,
     logoutPatient,
     forgotPassword,
     resetPassword,
     changePassword,
     deletePatient,
     getPatient,
     getAllPatients,
     updatePatient,
     requestAccessToPatientData,
     accessPatientDataWithCode,
     addPatientFile,
     getPatientFilesByHospitalId,
     getPatientFilesByDoctorId,
     getPatientFileById
     
    }