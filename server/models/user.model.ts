import mongoose from 'mongoose';
import crypto from 'crypto';

// create a user interface

interface User {
  name: string;
  email: string;
  hashed_password: string;
  salt: string;
  updated: Date;
  created: Date;
  educator: Boolean;
}

// create a schema for User.

const userSchema = new mongoose.Schema<User>({
  name: {
    type: String,
    trim: true,
    required: "Name can't be empty. :(",
  },
  email: {
    type: String,
    trim: true,
    unique: 'e-mail already exists. :/',
    match: [/.+\@.+\..+/, 'Kindly, enter an existing e-mail address. :/'],
    required: "E-mail can't be empty. :(",
  },
  hased_password: {
    type: String,
    required: "Password can't be empty. :(",
  },
  salt: {
    type: String,
  },
  updated: {
    type: Date,
  },
  created: {
    type: Date,
    default: Date.now,
  },
  educator: {
    type: Boolean,
    default: false,
  },
});

userSchema
  .virtual('password')
  .set(function (password) {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashed_password = this.encryptPassword(password);
  })
  .get(function () {
    return this._password;
  });

userSchema.path('hashed_password').validate(function (v) {
    if (this._password && this._password.lenth < 6) {
      this.invalidate('password', 'Password must be at least 10 characters long.');
    }
    if (this.isNew && !this._password) {
        this.invalidate('password', 'Password can\'t be empty. :(');
    }
}, null);

userSchema.methods = {
    authenticate: function (plainText) {
        return this.encryptPassword(plainText) === this.hashed_password;
    },
    encryptPassword: function (password) {
        if (!password) return '';
        try {
            return crypto.createHmac('sha1', this.salt).update(password).digest('hex');
        }
        catch(err) {
            return '';
            console.log(err);
        }
    },
    makeSalt: function () {
        return Math.round((new Date().valueOf() * Math.random())) + '';
    }
}

export default mongoose.model('User', userSchema);
