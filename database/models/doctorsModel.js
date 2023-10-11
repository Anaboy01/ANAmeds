const mongoose = require('mongoose');
const bcrypt = require('bcryptjs')

const doctorSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: [true, 'Please add a password'],
  },
  specialty: {
      type: String,
      required: true
  },
  licenseNumber: String, 
  contactInfo:{
      email: {
            type: String,
            required: [true, 'Please add an email'],
            trim: true,
            unique: true,
            match: [
              /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
              'Please enter a valid email',
            ]
      },
    phone: String,
  },
  isVerified:{
      type: Boolean,
      default: false
  },
  role:{
      type: String,
      enum:['doctor'],
      default: 'doctor'
  },
  hospitalId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Hospital', // Reference to the hospital model
      required: true,
    },
  doctorAgent: {
      type: Array,
      required: true,
      default: [],
    },
  rank:{
    type: String,
    required: true,
    default: 'FY1',
    enum:['FY1', 'FY2', 'ST', 'SpR', 'GPST', 'SHO', 'Consultant', 'Specialist']
  }
 
},
{
  timestamps: true,
  minimize: false,
  toJSON: { getters: true }, // Include virtuals when converting to JSON
}
);

doctorSchema.pre('save', async function (next) {
      if (!this.isModified('password')) {
        return next();
      }
    
      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(this.password, salt);
      this.password = hashedPassword;
    
      next();
    });

const Doctor = mongoose.model('Doctor', doctorSchema);

module.exports = Doctor;
