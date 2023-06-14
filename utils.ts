import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
config();

const signatureAccess = process.env.ACCESS_TOKEN_SECRET;
const signatureRefresh = process.env.REFRESH_TOKEN_SECRET;
if (!signatureAccess) {
	throw new Error('ACCESS_TOKEN_SECRET is not defined');
}
if (!signatureRefresh) {
	throw new Error('REFRESH_TOKEN_SECRET is not defined');
}
const accessTokenAge = Math.floor(Math.random() * (60 - 30 + 1)) + 30;
const refreshTokenAge = 60 * 60 * 24 * 30;

const tokens: { [key: string]: string } = {};

const getTokens = (login: string) => {
	const accessToken = jwt.sign({ login }, signatureAccess, {
		expiresIn: accessTokenAge,
	});
	const refreshToken = jwt.sign({ login }, signatureRefresh, {
		expiresIn: refreshTokenAge,
	});

	tokens[refreshToken] = login;

	return { accessToken, refreshToken };
};

const verifyToken = (token: string) => {
	try {
		const decoded = jwt.verify(token, signatureRefresh);
		const login = tokens[token];
		if (login) {
			return { login };
		} else {
			return null;
		}
	} catch (error) {
		return null;
	}
};

export { getTokens, verifyToken, accessTokenAge, refreshTokenAge };
