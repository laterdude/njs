var LocalStrategy = require('passport-local').Strategy;

var User = require('../app/models/user');

module.exports = function(passport){

	passport.serializeUser(function(user, done){
		done(null, user.id);
	});

	passport.deserializeUser(function(id, done){
		User.findById(id, function(err, user){
			done(err, user);
		});
	});

	passport.use('local-signup', new LocalStrategy({
		usernameField: 'email', // we named it email in the ejs file, the default is 'username'
		passwordField: 'password',
		passReqToCallback: true
	},
	function(req, email, password, done){
		process.nextTick(function(){
			User.findOne({'local.username': email}, function(err, user){
				if(err)
					return done(err);
				if(user){
					return done(null, false, req.flash('signupMessage', 'That email is already taken'));
				} else {
					newUser = new User();
					newUser.local.username = email; // not 'email' like above since the local db schema lists it as username
					// newUser.local.password = password; need to salt the password with bcrypt, see next line, method is acquired from user.js
					newUser.local.password = newUser.generateHash(password);

					newUser.save(function(err){
						if(err)
							throw err;
						return done(null, newUser);
					})
				}
			})
		});
	}));

	passport.use('local-login', new LocalStrategy({
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true
	},
	function(req, email, password, done){
		process.nextTick(function(){
			User.findOne({'local.username': email}, function(err, user){
				if(err)
					return done(err);
				if(!user)
					return done(null, false, req.flash('loginMessage', 'No User found'));
				// if(user.local.password != password) need to swap this out so that it uses the hashed password for comparison
				if(!user.validPassword(password)){
					return done(null, false, req.flash('loginMessage', 'invalid password'));
				}
				return done(null,  user);
			})
		})
	}
	))


}