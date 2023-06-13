import { MongoClient } from 'mongodb';
import { config } from 'dotenv';

config();

const URL = process.env.DATABASE_URL;
const DATABASE_NAME = 'be-auth';
if (!URL) {
	throw new Error('Database url not found');
}

export const client = new MongoClient(URL);
export const connectToDatabase = async () => {
	try {
		await client.connect();
		console.log('Connected to the database');
	} catch (err) {
		console.error('Failed to connect to the database:', err);
	}
};
const db = client.db(DATABASE_NAME);
export const users = db.collection('users');
export const tokens = db.collection('tokens');
