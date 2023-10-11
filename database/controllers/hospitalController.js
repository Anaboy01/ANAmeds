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
const Hospital = require('../models/hospitalsModel');
const Token = require('../models/tokenModel');

const cryptr = new Cryptr(process.env.CRYPTR_KEY)


const registerHospital = asyncHandler(async (req, res) => {
  const { name, email, password, state, city, country, phone, website, description } = req.body;

  // Validation
  if (!name || !email || !password) {
    res.status(400).json({ error: 'Please fill in all the required fields' });
    return;
  }

  if (password.length < 6) {
    res.status(400).json({ error: 'Password must be at least 6 characters long' });
    return;
  }

  // Check if hospital exists
  const hospitalExists = await Hospital.findOne({ 'contactInfo.email': email });

  if (hospitalExists) {
    res.status(400).json({ error: 'Email already in use' });
    return;
  }

  // Get user agent
  const ua = parser(req.headers['user-agent']);
  const hospitalAgent = ua.ua;

  // Hash the password



  // Create a new hospital user
  const hospital = await Hospital.create({
    name,
    password,
    location:{
      city: city,
      state: state,
      country: country
    },
    contactInfo: {
      email: email,
      phone: phone,
      website: website
    },
    hospitalAgent,
    description: description
  });

  // Generate Token
  const token = generateToken(hospital._id);

  // Send HTTP-only cookie
  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: 'none',
    secure: true,
  });

  // Return the hospital data in the response
  res.status(201).json({
    _id: hospital._id,
    name: hospital.name,
    contactInfo: hospital.contactInfo,
    location: hospital.location,
    description: description
    // Add other properties you want to return here
  });
});

const loginHospital = asyncHandler (async (req, res) => {
  const {email, password} = req.body
  //validation

  if (!email || !password){
        res.status(400);
        throw new Error('pls fill in all the required fields')
  }

  const hospital = await Hospital.findOne({'contactInfo.email': email});

  if (!hospital){
        res.status(404);
        throw new Error('user not found... pls sign up')
  }

  const passwordIsCorrect = await bcrypt.compare(password, hospital.password)

  if (!passwordIsCorrect){
        res.status(400);
        throw new Error('Invalid email or password')
  }

  // Trigger 2fa for unknown userAgent

  const ua = parser(req.headers['user-agent']);
  const thisHospitalAgent = ua.ua

  console.log(thisHospitalAgent)
  const allowedAgent = hospital.hospitalAgent.includes(thisHospitalAgent)

  if (!allowedAgent){

        // Generate 6 digit random code
        const loginCode = Math.floor(100000 + Math.random() * 900000)

        console.log(loginCode)


        // Encrypt login code before saving to database

        const encryptedLoginCode = cryptr.encrypt(loginCode.toString())

              // Delete token if it exists in DB
        let hospitalToken = await Token.findOne({ hospitalId: hospital._id });
        if (hospitalToken) {
        await hospitalToken.deleteOne();
        }
  
        // Save Token to DB
        await new Token({
        hospitalId: hospital._id,
        lToken: encryptedLoginCode,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
        }).save();

        res.status(400)
        throw new Error('New browser or device detected')


 

  }

  const token = generateToken(hospital._id)

  if(hospital && passwordIsCorrect){
        res.cookie('token', token,{
              path:'/',
              httpOnly: true,
              expires: new Date(Date.now() + 1000 * 86400), // 1 day
              sameSite: 'none',
              secure: true,
        })

        const {_id,
          name,
          contactInfo,
          location,
          description,
          role} = hospital

        res.status(200).json({
          _id,
          name,
          contactInfo,
          location,
          description,
          role
        })

  } else{
        res.status(500)
        throw new Error('something went wrong')
  }





})

const sendLoginCode = asyncHandler(async (req, res) => {
  const {email} = req.params
  const hospital = await Hospital.findOne({'contactInfo.email': email});


  if(!hospital){
        res.status(404)
        throw new Error('User not found')
  }

  // Find Login Code in DB
  let hospitalToken = await Token.findOne({ hospitalId: hospital._id,
  expiresAt: {$gt: Date.now()}
  });
  if(!hospitalToken){
        res.status(404)
        throw new Error('Invalid or Expired token, please login again')
  }

  const loginCode = hospitalToken.lToken;

  const decryptedLoginCode = cryptr.decrypt(loginCode);

  //Send Login Code

  const subject = "Login Access Code - AUTH:Z";
   const send_to = hospital.contactInfo.email;
   const sent_from = process.env.EMAIL_USER;
   const reply_to = "noreply@zinotrustacademy.com";
   const template = "loginCode";
   const name = hospital.name;
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


  const hospital = await Hospital.findOne({'contactInfo.email': email});


  if(!hospital){
        res.status(404);
        throw new Error('User not found')
  }

  // Find user login token

  const hospitalToken = await Token.findOne({
        hospitalId: hospital.id,
        expiresAt: { $gt: Date.now()},
  })

  if (!hospitalToken){
        res.status(404)
        throw new Error('Invalid token, pls log in again')
  }

  const decryptedLoginCode = cryptr.decrypt(hospitalToken.lToken);

  if (loginCode !== decryptedLoginCode) {

        res.status(400)
        throw new Error('incorrect login code')
        
  } else {
        //    Register user agent

        const ua = parser(req.headers['user-agent'])
        const thisHospitalAgent = ua.ua;

        hospital.hospitalAgent.push(thisHospitalAgent)

        await hospital.save()

        const token = generateToken(hospital._id)


// Send HTTP-only cookie

  res.cookie('token', token,{
        path:'/',
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: 'none',
        secure: true,
  })

  
  const {_id,
    name,
    contactInfo,
    location,
    description} = hospital

  res.status(200).json({
    _id,
    name,
    contactInfo,
    location,
    description
  })

  }
})

const hospitalLoginStatus = asyncHandler(async (req, res) => {
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

const logoutHospital = asyncHandler (async (req, res)=> { 
  res.cookie('token', '',{
        path:'/',
        httpOnly: true,
        expires: new Date(0), // 1 day
        sameSite: 'none',
        secure: true,
  });
  return res.status(200).json ({message: 'Logout successful'})
})

const getHospital = asyncHandler (async (req, res) => {
  const hospital = await Hospital.findById(req.hospital._id)

  if (hospital){

        const {_id,
          name,
          contactInfo,
          location,
          description,
        role} = hospital

        res.status(200).json({
          _id,
          name,
          contactInfo,
          location,
          description,
          role
        })

  }else{
        res.status(404)
        throw new Error('user not found')
  }
})

const updateHospital = asyncHandler(async (req, res) => {
  try {
    const hospital = await Hospital.findById(req.hospital._id);

    if (hospital) {
      hospital.name = req.body.name || hospital.name;

      hospital.contactInfo.phone = req.body.phone || hospital.contactInfo.phone;

      hospital.description = req.body.description || hospital.description;

      hospital.contactInfo.website = req.body.website || hospital.contactInfo.website ;

      hospital.location.country = req.body.country || hospital.location.country ;

      hospital.location.state = req.body.state || hospital.location.state ;

      hospital.location.city = req.body.city || hospital.location.city ;

    

      const updatedHospital = await hospital.save();
      res.status(200).json(updatedHospital);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

const deleteHospital = asyncHandler(async (req, res) => {
  try {
    const hospital = await Hospital.findById(req.params.id);

    if (!hospital) {
      return res.status(404).json({ message: 'Hospital not found' });
    }

    // Perform the deletion
    await hospital.deleteOne();

    res.status(200).json({ message: 'Hospital deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


const getAllHospitals = asyncHandler(async (req, res) => {
  const hospitals = await Hospital.find().sort('-createdAt').select('-password')

  if(!hospitals){
        res.status(500)
        throw new Error('Something went wrong')
  }
  res.status(200).json(hospitals)
})

const sendAutomatedEmail = asyncHandler(async(req, res) => {
            
  const {subject, send_to,reply_to, template, url} = req.body;

  if(!subject || !send_to || !reply_to || !template){
        res.status(500)
        throw new Error('missing email params')
  }

  // Get user

  const hospital = await Hospital.findOne({'contactInfo.email': send_to})

  if(!hospital){
        res.status(404)
        throw new Error('user not found')
  }

  const sent_from = process.env.EMAIL_USER
  const name = hospital.name
  const link = `${process.env.FRONTEND_URL} ${url}`

  try {
        await sendEmail(
        subject,
        // message,
        send_to,
        sent_from,
        reply_to,
        template,
        name,
        link
        )
        res.status(200).json({message: 'email sent'})
  } catch (error) {
        res.status(500)
        throw new Error('email not sent, pls try again')
  }

})

const forgotPassword = asyncHandler(async (req, res) => {
  const {email} = req.body

  const hospital = await Hospital.findOne({ 'contactInfo.email': email });


  if(!hospital){
        res.status(404)
        throw new Error('no user with this email')
  }

   // Delete token if it exists in DB
   let token = await Token.findOne({ hospitalId: hospital._id });
   if (token) {
     await token.deleteOne();
   }
 
   // Create Verification Token and save
   const resetToken = crypto.randomBytes(32).toString("hex") + hospital.id;

   console.log(resetToken)
 
   // Hash token before saving to DB
   const hashedToken = hashToken(resetToken);
 
   // Save Token to DB
   await new Token({
     hospitalId: hospital._id,
     rToken: hashedToken,
     createdAt: Date.now(),
     expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
   }).save();
 
   // Construct Reset Url
   const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;
 
  
   const subject = "Password Reset - AUTH:Z";
   const send_to = hospital.contactInfo.email;
   const sent_from = process.env.EMAIL_USER;
   const reply_to = "noreply@nigga.com";
   const template = "forgotPassword";
   const name = hospital.name;
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

  const hospitalToken = await Token.findOne({
        rToken: hashedToken,
        expiresAt: { $gt: Date.now()}

       
  })

  if(!hospitalToken){
        res.status(404)
        throw new Error('invalid or expired token')
  }

  // FIND USER

  const hospital = await Hospital.findOne({_id: hospitalToken.hospitalId})

  // Now reset password

  hospital.password = password
  await hospital.save()

  res.status(200).json({message: 'Password Reset Sucessful, please login'})

})

const changePassword = asyncHandler(async (req, res) => {
  const {oldPassword, password} = req.body  
const hospital = await Hospital.findById(req.hospital._id)

if(!hospital){
    res.status(404)
    throw new Error('no user with this email')
}

if (!oldPassword || !password){
    res.status(400)
    throw new Error('pls enter old and new password');
    
}

const passwordIsCorrect = await bcrypt.compare(oldPassword, hospital.password)

// Save new password

if (hospital && passwordIsCorrect) {

  hospital.password = password
    await hospital.save()

    res.status(200).json({message: 'password change succesful, pls re login'})
    
} else {
    res.status(400)
    throw new Error('old password incorrect')
}
})



module.exports = {
  registerHospital,
  loginHospital,
  logoutHospital,
  getHospital,
  updateHospital,
  deleteHospital,
  getAllHospitals,
  sendAutomatedEmail,
  forgotPassword,
  resetPassword,
  sendLoginCode,
  changePassword,
  loginWithCode,
  hospitalLoginStatus
}
