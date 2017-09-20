var passport= require('passport');

var localStrategy=require('passport-local').Strategy;

var User =require('../models/user');

passport.serializeUser(function(user,done){
	done(null,user.id);
});

passport.deserializeUser(function(id,done){
	User.findById(id,function(err,user){
			done(err,user);
	});
});

passport.use('local.signup', new localStrategy({
	usernameField: 'email',
	passwordField: 'password',
	passReqToCallback: true
},function(req,email,password,done){
	// console.log(User);
	User.findOne({'email': email},function(err,user){
		if(err){
			return done(err);
		}
		if(user){
			return done(null,false);
		}


		var newUser =new User();
		newUser.fullname= req.body.name;
		newUser.email= req.body.email;
		newUser.password= newUser.encryptPassword(req.body.password);

		newUser.save(function(err){
			if(err){
				return done(err);
			}
			return done(null,newUser);
		})
	})
}));

passport.use('local.login', new localStrategy({
	usernameField: 'email',
	passwordField: 'password',
	passReqToCallback: true
},function(req,email,password,done){
	//console.log(email);
	User.findOne({'email': email},function(err,user){
		if(err){
			return done(err);
		}
		if(!user){
			
			return done(null, false, req.flash('loginError', 'No user found.'));
		}

		if(!user.validPassword(req.body.password)){
	
			 return done(null, false, req.flash('passwordError', 'Oops! Wrong password.')); 
			};

			return done(null,user);

		 
	})
}));