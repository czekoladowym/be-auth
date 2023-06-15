import { UsersRepo } from '@/database/repositories/users';
import { Jwt } from '../utils/jwt';
import bcrypt from 'bcrypt';

export class AuthServices {
	constructor(private users: UsersRepo, private jwt = new Jwt()) {}

	async signUp(email: string, password: string) {
		const user = await this.users.get(email);
		if (user) {
			throw new Error('User already exists');
		}
		const hashedPassword = await bcrypt.hash(password, 10);
		await this.users.create(email, hashedPassword);
	}
	async login(email: string, password: string) {
		const user = await this.users.get(email);
		if (!user) {
			throw new Error('User not found');
		}
		const isPasswordValid = await bcrypt.compare(password, user.password);
		if (!isPasswordValid) {
			throw new Error('Unauthorized');
		}
		const accessToken = this.jwt.generateAccess(email);
		const refreshToken = this.jwt.generateRefresh(email);
		return {
			accessToken,
			refreshToken,
		};
	}
	async refresh(refreshToken: string) {
		const verify = this.jwt.validateRefresh(refreshToken);
		if (!verify) {
			throw new Error('Invalid token');
		}
		const email = verify.login;
		const userExists = await this.users.get(email);
		if (!userExists) {
			throw new Error('User not found');
		}
		const accessToken = this.jwt.generateAccess(email);
		return accessToken;
	}
	async validate(accessToken: string) {
		const verify = this.jwt.validateAccess(accessToken);
		if (!verify) {
			throw new Error('Invalid token');
		}
		const email = verify.login;
		const userExists = await this.users.get(email);
		if (!userExists) {
			throw new Error('User not found');
		}
		return email;
	}
}
