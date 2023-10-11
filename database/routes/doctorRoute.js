const express = require('express');
const { doctorProtect, doctorAdminOnly, hospitalProtect } = require('../middleware/authMiddleware');
const { registerDoctor, loginDoctor, logoutDoctor, getDoctor, getAllDoctors, getDoctorsByHospitalId, getDoctorByEmailAndHospitalId, updateDoctor, loginWithCode, deleteDoctor, changeDoctorStatus, loginStatus, sendLoginCode, forgotPassword, resetPassword, changePassword } = require('../controllers/doctorController');


const doctorRouter = express.Router()


doctorRouter.post('/registerDoctor',hospitalProtect, registerDoctor)
doctorRouter.post('/loginDoctor', loginDoctor)
doctorRouter.post('/sendLoginCode/:email', sendLoginCode)
doctorRouter.post('/loginWithCode/:email', loginWithCode),
doctorRouter.get('/loginStatus',loginStatus)
doctorRouter.get('/logoutDoctor', logoutDoctor)
doctorRouter.get('/getDoctor', doctorProtect, getDoctor)
doctorRouter.get('/getAllDoctors',doctorProtect,doctorAdminOnly, getAllDoctors)


doctorRouter.get('/getDoctorsByHospitalId',hospitalProtect, getDoctorsByHospitalId),
doctorRouter.get('/getDoctorByEmailAndHospitalId',hospitalProtect,getDoctorByEmailAndHospitalId),

doctorRouter.patch('/updateDoctor', doctorProtect, updateDoctor),
doctorRouter.delete('/:id',hospitalProtect, deleteDoctor)
doctorRouter.patch('/changeDoctorStatus/:doctorId',hospitalProtect, changeDoctorStatus)

doctorRouter.post('/forgotPassword',forgotPassword)
doctorRouter.patch('/resetPassword/:resetToken', resetPassword)
doctorRouter.patch('/changePassword',doctorProtect, changePassword)




module.exports = doctorRouter