const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../models/user');

const BCRYPT_SECRET = process.env.BCRYPT_SECRET;

const generateToken = (username) => {
	const timestamp = new Date().getTime();

	// sub is the subject; iat is the issued at time
	return jwt.sign({ sub: username, iat: timestamp }, BCRYPT_SECRET);
};

exports.login = (req, res, next) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res
			.status(422)
			.json({ message: 'You must provide an email and password' });
	}

	User.findByPk(username)
		.then((user) => {
			if (!user) {
				return res.status(423).json({
					message: 'Invalid username or password',
				});
			}

			bcrypt.compare(password, user.password).then((match) => {
				if (!match) {
					return res.status(423).json({
						message: 'Invalid username or password',
					});
				}

				return res.status(201).json({
					message: 'Login successful',
					token: generateToken(username),
				});
			});
		})
		.catch((err) => {
			console.log(`[ AUTH MICROSERVICE : LOGIN ERROR ]`);
			next(err);
		});
};

exports.signup = (req, res, next) => {
	const { username, password, confirmPassword } = req.body;

	if (password !== confirmPassword) {
		return res.status(422).json({ message: 'Passwords do not match' });
	}

	if (!username || !password) {
		return res
			.status(422)
			.json({ message: 'You must provide an email and password' });
	}

	User.findByPk(username)
		.then((user) => {
			if (user) {
				return res.status(421).json({
					message: 'Username taken.',
				});
			}

			return bcrypt
				.hash(password, 16)
				.then((hashedPassword) => {
					return User.create({
						username,
						password: hashedPassword,
					});
				})
				.then((newUser) => {
					return newUser.save();
				})
				.then(() => {
					res.status(201).json({
						message: 'New user created successfully',
						token: generateToken(username),
					});
				});
		})
		.catch((err) => {
			console.log(`[ AUTH MICROSERVICE : LOGIN ERROR ]`);
			next(err);
		});
};
