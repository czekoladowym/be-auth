import { Router } from 'express';

abstract class Controller {
	path: string;
	router: Router;
	constructor(path: string) {
		this.path = path;
		this.router = Router();
	}
}
export default Controller;
