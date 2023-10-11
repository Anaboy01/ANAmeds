const express = require('express');


const {registerHospital, loginHospital, logoutHospital, getHospital, updateHospital, deleteHospital, getAllHospitals, sendAutomatedEmail, forgotPassword, resetPassword, sendLoginCode, changePassword, loginWithCode, hospitalLoginStatus} = require('../controllers/hospitalController');
const { hospitalProtect, hospitalAdminOnly } = require('../middleware/authMiddleware');
const hospitalRouter = express.Router()

hospitalRouter.post('/registerHospital', registerHospital)
hospitalRouter.post('/loginHospital', loginHospital)
hospitalRouter.get('/logoutHospital', logoutHospital)
hospitalRouter.get('/hospitalloginStatus',hospitalLoginStatus)
hospitalRouter.get('/getHospital',hospitalProtect, getHospital)


hospitalRouter.patch('/updateHospital',hospitalProtect, updateHospital),
hospitalRouter.delete('/:id',hospitalProtect, hospitalAdminOnly, deleteHospital)
hospitalRouter.get('/getAllHospitals',hospitalProtect,hospitalAdminOnly, getAllHospitals)
hospitalRouter.post('/sendAutomatedEmail',hospitalProtect,sendAutomatedEmail)
hospitalRouter.post('/forgotPassword',forgotPassword)

hospitalRouter.patch('/resetPassword/:resetToken', resetPassword)
hospitalRouter.patch('/changePassword',hospitalProtect, changePassword)
hospitalRouter.post('/sendLoginCode/:email', sendLoginCode)
hospitalRouter.post('/loginWithCode/:email', loginWithCode)




module.exports = hospitalRouter