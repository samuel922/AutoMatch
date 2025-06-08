import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient();

const connectDB = async () => {
  try {
    await prisma.$connect();
    console.log('PostgreSQL connected via Prisma');
  } catch (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
};

export default connectDB;
