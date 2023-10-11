const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Corrected bcrypt import

// Define the patient_file schema

const patientFileSchema = new mongoose.Schema(
  {
    _id:{
      type: Number
    },
    fileName: String,
    prescriptions: [String], // You can modify the data type as needed
    diagnosis: String,
    tests: [
      {
        test:{
          type: String
        },
        testResults:{
          type:String
        },
        
      }
    ], // You can modify the data type as needed
    note: String,
    doctorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Doctor'
    },
    hospitalId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Hospital'
    },
    doctorName: {
      type: String,
      
    },
    role:{
      type: String,
      default: 'patient',
      enum:['patient', 'admin']

    },
    hospitalName: {
      type:String,
      
    },
    images: [String], // Assuming image URLs or paths as strings
    videos: [String]  // Assuming video URLs or paths as strings
  },
  {
    timestamps: true,
    minimize: false,
    toJSON: { getters: true }
  }
);



const  patientSchema = mongoose.Schema(
  {
    name: {
     firstName:{
      type: String,
      required: true
     },
     lastName:{
      type: String,
      required: true
     },
  
    },
    contactInfo:{
      email: {
        type: String,
        required: [true, 'Please add an email'],
        trim: true,
        unique: true,
        match: [
          /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
          'Please enter a valid email',
        ],
      },
      phone: {
        type: String,
        default: '+234',
      },
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
    },
    photo: {
      type: String,
      required: [true, 'Please add a photo'],
      default: 'https://i.ibb.co/4pDNDk1/avatar.png',
    },
    role:{
      type: String,
      required: true,
      enum:['patient', 'admin'],
      default: 'patient'
  },
    patientAgent: {
      type: Array,
      required: true,
      default: [],
    },
    patient_files:[
      patientFileSchema
    ],
    accessCode:{
      type:String
    },
    accessCodeTimestamp: {
      type: Date, // Store the timestamp when the access code was generated
    },
    isVerified:{
      type: Boolean,
      required: true,
      default: false
    }
  },
  {
    timestamps: true,
    minimize: false,
    toJSON: { getters: true }, // Include virtuals when converting to JSON
  }
);

// Add a pre-save hook to hash the password before saving
patientSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;

  next();
});

const Patient = mongoose.model('Patient', patientSchema);

module.exports = Patient;


