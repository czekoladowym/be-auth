import 'dotenv/config';
import App from './app';
import { AuthController } from './controllers/auth';
import { UsersRepo } from './database/repositories/users';
import { AuthServices } from './services/auth';
import { users } from './database';

const main = async () => {
	const usersDb = new UsersRepo(users);
	const authService = new AuthServices(usersDb);
	const authController = new AuthController(authService);
	const controllers = [authController];
	const app = new App(3000, controllers);

	app.start();
};
main();
