import pymongo


def open_client(mongo_url):
	mongo_client = pymongo.MongoClient(mongo_url)
	return mongo_client


def get_database(mongo_client, db_name):
	db = mongo_client[db_name]
	return db


def get_collection(db, collection_name):
	db_col = db[collection_name]
	return db_col


def upsert_data(db_col, data):
	role = {'role': data['role']}
	db_col.update_one(role, {'$set': data}, upsert=True)


def insert_or_update(mongo_client, db_name, collection_name, data):
	db = get_database(mongo_client, db_name)
	db_col = get_collection(db, collection_name)
	upsert_data(db_col, data)


def get_resources_from_role(mongo_client, db_name, collection_name, role):
	db = get_database(mongo_client, db_name)
	db_col = get_collection(db, collection_name)
	data = db_col.find_one(role)
	return data['resources']
