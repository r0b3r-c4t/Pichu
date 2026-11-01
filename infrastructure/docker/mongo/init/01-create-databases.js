const serviceUsers = [
  {
    database: 'identity_db',
    username: 'identity_user',
    password: process.env.IDENTITY_DB_PASSWORD,
  },
  {
    database: 'vehicle_db',
    username: 'vehicle_user',
    password: process.env.VEHICLE_DB_PASSWORD,
  },
  {
    database: 'device_db',
    username: 'device_user',
    password: process.env.DEVICE_DB_PASSWORD,
  },
  {
    database: 'automation_db',
    username: 'automation_user',
    password: process.env.AUTOMATION_DB_PASSWORD,
  },
];

for (const serviceUser of serviceUsers) {
  if (!serviceUser.password) {
    throw new Error(`Missing password for ${serviceUser.username}`);
  }
}

for (const serviceUser of serviceUsers) {
  const serviceDatabase = db.getSiblingDB(serviceUser.database);
  serviceDatabase.createUser({
    user: serviceUser.username,
    pwd: serviceUser.password,
    roles: [{ role: 'readWrite', db: serviceUser.database }],
  });
}
