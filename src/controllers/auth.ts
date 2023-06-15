import { signUpCheck } from '../middleware/auth';
import Controller from '.';
import { AuthServices } from '../services/auth';
import { Request, Response } from 'express';
import { validationResult } from 'express-validator';

export class AuthController extends Controller {
	constructor(private auth: AuthServices) {
		super('/auth');
		this.router.post('/signup', signUpCheck, this.signUp);
		this.router.post('/login', signUpCheck, this.login);
		this.router.post('/refresh', this.refresh);
		this.router.get('/me', this.me);
	}
	signUp = async (req: Request, res: Response) => {
		const { email, password } = req.body;
		try {
			const validation = validationResult(req);
			if (!validation.isEmpty()) {
				return res.status(400).json({
					message: 'Validation error',
					errors: validation.array(),
				});
			}
			await this.auth.signUp(email, password);
			return res.status(201).json({
				message: 'User created',
			});
		} catch (e) {
			console.log(e);
			res.status(500).json({ message: 'Something went wrong, try again' });
		}
	};
	private login = async (req: Request, res: Response) => {
		const { email, password } = req.body;
		const tokens = await this.auth.login(email, password);
		return res.status(200).json({
			message: 'User logged in',
			accessToken: tokens.accessToken,
			refreshToken: tokens.refreshToken,
		});
	};
	private refresh = async (req: Request, res: Response) => {
		try {
			const { refreshToken } = req.body;
			if (!refreshToken)
				return res.status(400).json({ message: 'Token missed' });
			const accessToken = await this.auth.refresh(refreshToken);
			res.status(200).json({ accessToken });
		} catch (e) {
			console.log(e);
			res.status(500).json({ message: 'Something went wrong, try again' });
		}
	};
	private me = (req: Request, res: Response) => {
		try {
			const accessToken = req.headers.authorization?.split(' ')[1];
			if (!accessToken)
				return res.status(400).json({ message: 'Token missed' });
			const email = this.auth.validate(accessToken);
			if (!email) return res.status(400).json({ message: 'Invalid token' });
			return res.status(200).json({ email });
		} catch (e) {
			console.log(e);
			res.status(500).json({ message: 'Something went wrong, try again' });
		}
	};
}
