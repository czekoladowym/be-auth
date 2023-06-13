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

app.post('/sign_up', async (req: Request, res: Response) => {
	const user = req.body;
	const { username } = req.body;

	try {
		const existingUser = await users.findOne({ username });
		if (existingUser) {
			console.log(existingUser);
			return res.status(409).send('User already registered');
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
});

app.get('/all', async (req: Request, res: Response) => {
	try {
		console.log(await users.findOne({}));
	} catch (err) {
		console.log(err);
		res.status(500).send('Internal Server Error');
	}
});

app.post('/login', async (req: Request, res: Response) => {
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
});

app.post('/refresh', async (req: Request, res: Response) => {
	try {
		const refreshToken = req.cookies.refreshToken;
		if (!refreshToken) {
			return res.status(401).send('Refresh token not found');
		}
		const decodedRefreshToken = verifyToken(refreshToken);
		if (!decodedRefreshToken) {
			return res.status(401).send('Invalid refresh token');
		}
		const { login } = decodedRefreshToken;
		const user = await users.findOne({ username: login });
		if (!user) {
			return res.status(401).send('User not found');
		}

		const storedToken = await tokens.findOne({
			refreshToken,
			userId: user._id,
		});
		if (!storedToken) {
			return res.status(401).send('Invalid refresh token');
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
});

app.post('/logout', async (req: Request, res: Response) => {
	try {
		const refreshToken = req.cookies.refreshToken;
		if (!refreshToken) {
			return res.status(401).send('Refresh token not found');
		}

		const decodedRefreshToken = verifyToken(refreshToken);
		if (!decodedRefreshToken) {
			return res.status(401).send('Invalid refresh token');
		}

		const { login } = decodedRefreshToken;
		const user = await users.findOne({ username: login });
		if (!user) {
			return res.status(401).send('User not found');
		}

		const deleteResult = await tokens.deleteOne({
			refreshToken,
			userId: user._id,
		});
		if (!deleteResult) {
			return res.status(500).send('Internal Server Error');
		}

		res.clearCookie('refreshToken');
		res.status(200).send('Logout successful');
	} catch (err) {
		console.log(err);
		res.status(500).send('Internal Server Error');
	}
});

connectToDatabase().then(() => {
	app.listen(PORT, () => {
		console.log(`Listening on port ${PORT}`);
	});
});
