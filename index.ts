import bodyParser from 'body-parser';
import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { getTokens, refreshTokenAge, verifyToken } from './utils';
import { connectToDatabase, users, tokens } from './src/database';
import cookieParser from 'cookie-parser';
import cookie from 'cookie';

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(cookieParser());

class Server {
	private app: express.Application;
	private readonly PORT: number;

	constructor(port: number) {
		this.PORT = port;
		this.app = express();
		this.configureMiddleware();
		this.configureRoutes();
		this.connectToDatabase();
	}

	private configureMiddleware(): void {
		this.app.use(express.json());
		this.app.use(cookieParser());
	}

	private configureRoutes(): void {
		this.app.post('/sign_up', this.signUpHandler);
		this.app.get('/all', this.getAllHandler);
		this.app.post('/login', this.loginHandler);
		this.app.post('/refresh', this.refreshHandler);
		this.app.post('/logout', this.logoutHandler);
	}

	private async signUpHandler(req: Request, res: Response): Promise<void> {
		const user = req.body;
		const { username } = req.body;

		try {
			const existingUser = await users.findOne({ username });
			if (existingUser) {
				console.log(existingUser);
				res.status(409).send('User already registered');
				return;
			}

			const hashedPassword = await bcrypt.hash(user.password, 10);
			user.password = hashedPassword;
			const result = await users.insertOne(user);

			console.log(result);
			res.status(200).send('User registered successfully');
		} catch (err) {
			console.log(err);
			res.status(500).send('Internal Server Error');
		}
	}

	private async getAllHandler(req: Request, res: Response): Promise<void> {
		try {
			console.log(await users.findOne({}));
		} catch (err) {
			console.log(err);
			res.status(500).send('Internal Server Error');
		}
	}

	private async loginHandler(req: Request, res: Response): Promise<void> {
		const { username, password } = req.body;
		const { accessToken, refreshToken } = getTokens(username);

		try {
			const user = await users.findOne({ username });

			if (!user) {
				res.status(404).send('User not registered yet');
				return;
			}

			const passMatch = await bcrypt.compare(password, user.password);
			if (!passMatch) {
				res.status(400).send('Invalid username or password');
				return;
			}

			const tokenResult = await tokens.insertOne({
				refreshToken,
				userId: user._id,
			});
			if (!tokenResult) {
				res.status(500).send('Internal Server Error');
				return;
			}

			res.setHeader(
				'Set-Cookie',
				cookie.serialize('refreshToken', refreshToken, {
					httpOnly: true,
					maxAge: refreshTokenAge,
				})
			);
			res.status(200).send(accessToken);
		} catch (err) {
			console.log(err);
			res.status(500).send('Internal Server Error');
		}
	}

	private async refreshHandler(req: Request, res: Response): Promise<void> {
		try {
			const refreshToken = req.cookies.refreshToken;
			if (!refreshToken) {
				res.status(401).send('Refresh token not found');
				return;
			}
			const decodedRefreshToken = verifyToken(refreshToken);
			if (!decodedRefreshToken) {
				res.status(401).send('Invalid refresh token');
				return;
			}
			const { login } = decodedRefreshToken;
			const user = await users.findOne({ username: login });
			if (!user) {
				res.status(401).send('User not found');
				return;
			}

			const storedToken = await tokens.findOne({
				refreshToken,
				userId: user._id,
			});
			if (!storedToken) {
				res.status(401).send('Invalid refresh token');
				return;
			}

			const { accessToken, refreshToken: newRefreshToken } = getTokens(login);

			const updateResult = await tokens.updateOne(
				{ _id: storedToken._id },
				{ $set: { refreshToken: newRefreshToken } }
			);
			if (!updateResult) {
				res.status(500).send('Internal Server Error');
				return;
			}

			res.setHeader(
				'Set-Cookie',
				cookie.serialize('refreshToken', newRefreshToken, {
					httpOnly: true,
					maxAge: refreshTokenAge,
				})
			);

			res.status(200).send(accessToken);
		} catch (err) {
			console.log(err);
			res.status(500).send('Internal Server Error');
		}
	}

	private async logoutHandler(req: Request, res: Response): Promise<void> {
		try {
			const refreshToken = req.cookies.refreshToken;
			if (!refreshToken) {
				res.status(401).send('User is already logged out');
				return;
			}

			const decodedRefreshToken = verifyToken(refreshToken);
			if (!decodedRefreshToken) {
				res.status(401).send('Invalid refresh token');
				return;
			}

			const { login } = decodedRefreshToken;
			const user = await users.findOne({ username: login });
			if (!user) {
				res.status(401).send('User not found');
				return;
			}

			const deleteResult = await tokens.deleteOne({
				refreshToken,
				userId: user._id,
			});
			if (!deleteResult) {
				res.status(500).send('Internal Server Error');
			}

			res.clearCookie('refreshToken');
			res.status(200).send('Logout successful');
		} catch (err) {
			console.log(err);
			res.status(500).send('Internal Server Error');
		}
	}

	private async connectToDatabase(): Promise<void> {
		try {
			await connectToDatabase();
			this.app.listen(this.PORT, () => {
				console.log(`Listening on port ${this.PORT}`);
			});
		} catch (error) {
			console.log('Failed to connect to the database:', error);
		}
	}
}
const server = new Server(PORT);
