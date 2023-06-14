import { Collection, Document } from 'mongodb';

export class UsersRepo {
	constructor(private collection: Collection<Document>) {}
	create = async (email: string, password: string) => {
		await this.collection.insertOne({ email, password });
	};
	get = async (email: string) => {
		return await this.collection.findOne({ email });
	};
}
