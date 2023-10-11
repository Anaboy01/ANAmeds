const mongoose = require('mongoose')


const TokenSchema = mongoose.Schema(
      {
            hospitalId:{
                  type: mongoose.Schema.Types.ObjectId,
                  ref: 'Hospital'
            },
            patientId:{
                  type: mongoose.Schema.Types.ObjectId,
                  ref: 'Patient'
            },
            doctorId:{
                  type: mongoose.Schema.Types.ObjectId,
                  ref: 'Doctor'
            },
            vToken:{
                  type: String,
                  default: '',
            },
            rToken:{
                  type: String,
                  default: ''
            },
            lToken:{
                  type: String,
                  default: ''
            },
            accessToken:{
                  type: String,
                  default: '' 
            },
            createdAt:{
                  type: Date,
                  required: true
            },
            expiresAt:{
                  type: Date,
                  required:true
            },
           
            
      }
)




const Token = mongoose.model('Token', TokenSchema);

module.exports = Token;