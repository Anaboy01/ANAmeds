const mongoose = require('mongoose');
const bcrypt = require('bcryptjs')

// Define the hospital schema
const hospitalSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  password: {
      type: String,
      required: [true, 'Please add a password'],
      },
  location: {
    country: {
      type: String,
      required: true,
      trim: true,
    },
    state:{
      type: String,
      required: true,
      trim: true,
    },
    city: {
      type: String,
      required: true,
      trim: true,
    },
   
    postalCode: {
      type: String,
      trim: true,
    },
  },
  description: {
    type: String,
    required: true,
  },
  contactInfo: {
    phone: {
      type: String,
      trim: true,
    },
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
    website: {
      type: String,
      trim: true,
    },
  },
  departments: [
    {
      type: String,
      trim: true,
    },
  ],
  doctors: [
    {
      name: {
        type: String,
        trim: true,
      },
      specialty: {
        type: String,
        trim: true,
      },
    },
  ],
  hospitalAgent: {
    type: Array,
    required: true,
    default: [],
  },
  role:{
    type: String,
    default:'hospital',
    enum:['hospital', 'admin']
  },
  isVerified:{
    type:Boolean,
    default: false
  }
},
{
      timestamps: true,
      minimize: false,
      toJSON: { getters: true }, // Include virtuals when converting to JSON
}
);

hospitalSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;

  next();
});

// Create the Hospital model
const Hospital = mongoose.model('Hospital', hospitalSchema);

module.exports = Hospital;
