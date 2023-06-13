import { check } from 'express-validator';
export const signUpCheck = [
	check('email', 'Email is not valid').isEmail().isLength({ min: 5, max: 30 }),
	check('password', 'Password is not valid').isStrongPassword({
		minLength: 8,
		minLowercase: 1,
		minUppercase: 1,
		minNumbers: 1,
		minSymbols: 1,
	}),
];
