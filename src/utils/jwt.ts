import jwt from 'jsonwebtoken';
interface IValidatePayload {
	login: string;
	iat: number;
	exp: number;
}

export class Jwt {
	private accessSecret: string;
	private refreshSecret: string;
	constructor() {
		if (!process.env.ACCESS_TOKEN_SECRET) {
			throw new Error('ACCESS_TOKEN_SECRET is not defined');
		}
		if (!process.env.REFRESH_TOKEN_SECRET) {
			throw new Error('REFRESH_TOKEN_SECRET is not defined');
		}
		this.accessSecret = process.env.ACCESS_TOKEN_SECRET;
		this.refreshSecret = process.env.REFRESH_TOKEN_SECRET;
	}
	generateAccess(login: string) {
		const payload = {
			login,
		};
		const accessToken = jwt.sign(payload, this.accessSecret, {
			expiresIn: '1d',
		});
		return accessToken;
	}
	generateRefresh(login: string) {
		const payload = {
			login,
		};
		const refreshToken = jwt.sign(payload, this.refreshSecret, {
			expiresIn: '7d',
		});
		return refreshToken;
	}
	validateAccess(token: string) {
		return jwt.verify(token, this.accessSecret) as IValidatePayload;
	}
	validateRefresh(token: string) {
		return jwt.verify(token, this.refreshSecret) as IValidatePayload;
	}
}
