# Backend - Task Manager

A Node.js backend for the Task Manager application using Express, TypeORM, and PostgreSQL.

## Features

- User authentication with JWT
- Database management using TypeORM and PostgreSQL
- Secure password handling with bcrypt
- Environment-based configuration with dotenv
- CORS enabled for frontend communication

## Prerequisites

Make sure you have the following installed:

- [Node.js](https://nodejs.org/) (Latest LTS recommended)
- [PostgreSQL](https://www.postgresql.org/)
- [Git](https://git-scm.com/)

## Setup Instructions

### 1. Clone the Repository

```sh
git clone https://github.com/YOUR_GITHUB_USERNAME/backend.git
cd backend
```

### 2. Install Dependencies

```sh
npm install
```

### 3. Create a `.env` File

Create a `.env` file in the root directory and add the following variables:

```
PORT=5000
DB_USER=your_database_username
DB_HOST=your_database_connection_string
DB_NAME=your_database_name
DB_PASS=your_database_password
DB_PORT=5432

JWT_SECRET=your_secret_key
REFRESH_SECRET=your_refresh_secret
```

Replace `your_database_username`, `your_database_connection_string`, `your_database_name`, `your_database_password`, `your_secret_key` and `your_refresh_secret` with your actual values.

### 4. Run Database Migrations

```sh
npm run build
npm run typeorm migration:run
```

### 5. Start the Development Server

```sh
npm run dev
```

### 6. Build for Production

```sh
npm run build
```

### 7. Start the Production Server

```sh
npm start
```

## License

Copyright (c) 2025 [Deepraj Sarkar]
