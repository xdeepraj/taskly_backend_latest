import "reflect-metadata";
import { DataSource } from "typeorm";
import dotenv from "dotenv";

dotenv.config();

export const AppDataSource = new DataSource({
  type: "postgres",
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  username: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  synchronize: false,
  migrationsRun: true,
  logging: ["error", "warn"],
  entities: ["src/entities/*.ts"], // Load entities
  migrations: ["src/migrations/*.ts"], // Load migrations
  subscribers: [],
  extra: {
    ssl: {
      rejectUnauthorized: false, // Required for some cloud providers like Render
    },
  },
});

AppDataSource.initialize()
  .then(() => {
    console.log("📦 Database connected successfully!");
  })
  .catch((error) => console.log("Database connection error: ", error));

// import { Pool } from "pg";
// import dotenv from "dotenv";

// dotenv.config();

// const pool = new Pool({
//   user: process.env.DB_USER,
//   host: process.env.DB_HOST,
//   database: process.env.DB_NAME,
//   password: process.env.DB_PASS,
//   port: Number(process.env.DB_PORT),
//   ssl: {
//     rejectUnauthorized: false, // Allow self-signed certificates (use only for development)
//   },
// });

// export default pool;
