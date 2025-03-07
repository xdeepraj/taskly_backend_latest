import express, { Request, Response, NextFunction } from "express";
// import pool from "../db";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { AppDataSource } from "../db";

import { User } from "../entities/User";
import { Task } from "../entities/Task";

const router = express.Router();

export const userRepository = AppDataSource.getRepository(User);
export const taskRepository = AppDataSource.getRepository(Task);

const generateAccessToken = (username: string) => {
  return jwt.sign({ username }, process.env.JWT_SECRET as string, {
    expiresIn: "30m",
  });
};

const generateRefreshToken = (username: string) => {
  return jwt.sign({ username }, process.env.REFRESH_SECRET as string, {
    expiresIn: "3d",
  });
};

// ******************* Using TypeORM *************************************

const generateUsername = async (firstname: string, lastname: string) => {
  const baseUsername =
    firstname.slice(0, 4).toLowerCase() + lastname.slice(0, 4).toLowerCase();
  let username = baseUsername;
  let count = 1;

  while (true) {
    const existingUser = await userRepository.findOne({ where: { username } });
    if (!existingUser) break;

    username = `${baseUsername}${count}`;
    count++;
  }

  return username;
};

const fetchRefreshTokenFromDB = async (
  req: Request,
  res: Response,
  next: NextFunction,
  expiredAccessToken: string
) => {
  console.error("expiredAccessToken:", expiredAccessToken);

  try {
    const decoded: any = jwt.decode(expiredAccessToken);
    if (!decoded || !decoded.username) {
      return res.status(403).json({ error: "Invalid token structure" });
    }

    const username = decoded.username;

    // Fetch user from DB using TypeORM
    const user = await userRepository.findOne({
      where: { username },
      select: ["refreshToken"], // Only fetch refreshToken to optimize query
    });

    if (!user || !user.refreshToken) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    // Verify refresh token
    const verifyRefreshToken: any = jwt.verify(
      user.refreshToken,
      process.env.REFRESH_SECRET as string
    );

    // Generate new access token
    const newAccessToken = generateAccessToken(verifyRefreshToken.username);

    // Attach new access token to response headers
    res.setHeader("x-new-access-token", newAccessToken);
    req.body.username = verifyRefreshToken.username;
    next();
  } catch (error) {
    console.error("Refresh Token Error:", error);
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
};

const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET as string);

    req.body.username = decoded.username;
    next();
  } catch (error: any) {
    console.error("Authentication Error:", error);
    if (error.name === "TokenExpiredError") {
      return fetchRefreshTokenFromDB(req, res, next, token);
    }
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

router.get("/", (req: Request, res: Response) => {
  res.json({ message: "Task API is working!" });
});

// User Registration
router.post("/register", async (req: Request, res: Response) => {
  try {
    const { firstname, lastname, email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email & password fields are required" });
    }

    // Check if email already exists
    const existingUser = await userRepository.findOne({ where: { email } });

    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a unique username
    const username = await generateUsername(firstname, lastname);

    // Generate refresh token
    const refreshToken = generateRefreshToken(username);

    // Create new user instance
    const newUser = userRepository.create({
      firstname,
      lastname,
      email,
      password: hashedPassword,
      username,
      refreshToken,
    });

    // Save user to database
    await userRepository.save(newUser);

    return res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Registration Error:", error);
    return res.status(500).json({ error: "Error registering user" });
  }
});

// User Login
router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const user = await userRepository.findOne({ where: { email } });

    if (!user) {
      return res.status(400).json({ error: "Invalid email id. Try again!!!" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Wrong password. Try again!!!" });
    }

    // Step 1: Check if the existing refresh token is valid
    if (user.refreshToken) {
      try {
        jwt.verify(user.refreshToken, process.env.REFRESH_SECRET as string);
      } catch (err) {
        user.refreshToken = generateRefreshToken(user.username);
        await userRepository.save(user);
      }
    } else {
      // Step 2: If no refresh token exists, generate one
      user.refreshToken = generateRefreshToken(user.username);
      await userRepository.save(user);
    }

    // Step 3: Generate a new access token
    const accessToken = generateAccessToken(user.username);

    return res.json({
      message: "Login successful.",
      accessToken: accessToken,
      userData: user,
    });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ error: "Error logging in" });
  }
});

// Generate access token
router.post("/refresh", async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token required" });
    }

    // Find user with this refresh token
    const user = await userRepository.findOne({ where: { refreshToken } });

    if (!user) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    // Verify refresh token
    jwt.verify(
      refreshToken,
      process.env.REFRESH_SECRET as string,
      (err: any, decoded: any) => {
        if (err) {
          return res.status(403).json({ error: "Invalid refresh token" });
        }

        // Generate new access token
        const accessToken = generateAccessToken(decoded.username);

        return res.json({
          message: "New access token generated.",
          tokens: {
            accessToken: accessToken,
          },
        });
      }
    );
  } catch (error) {
    console.error("Refresh Token Error:", error);
    return res.status(500).json({ error: "Error refreshing token" });
  }
});

// Store task
router.post(
  "/addTask",
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const {
        task_id,
        username,
        task_priority,
        datetime,
        task_description,
        is_completed,
      } = req.body;

      const accessUsername = req.body.username;

      if (accessUsername !== username) {
        return res.status(403).json({ error: "Username is different." });
      }

      const task = taskRepository.create({
        task_id,
        username,
        task_priority,
        datetime,
        task_description,
        is_completed,
      });

      await taskRepository.save(task);

      return res.json({ message: "Task added successfully." });
    } catch (error) {
      console.error("Error:", error);
      return res.status(500).json({ error: "Task adding failed." });
    }
  }
);

// Fetch tasks by username
router.get(
  "/getTasks",
  authenticateToken,
  async (req: Request, res: Response) => {
    const { username } = req.query;

    if (!username || typeof username !== "string") {
      return res.status(400).json({ error: "Username is required" });
    }

    try {
      const tasks = await taskRepository.find({ where: { username } });

      return res.json({ message: "Task fetching successful.", tasks });
    } catch (error) {
      console.error("Error fetching tasks:", error);
      return res.status(500).json({ error: "Failed to fetch tasks" });
    }
  }
);

// Delete task or tasks
router.delete(
  "/deleteTask",
  authenticateToken,
  async (req: Request, res: Response) => {
    const { username, task_id } = req.query;

    if (!username || typeof username !== "string") {
      return res.status(400).json({ error: "Username is required" });
    }

    try {
      if (task_id) {
        // Delete specific task
        const result = await taskRepository.delete({
          username,
          task_id: task_id as string,
        });

        if (result.affected && result.affected > 0) {
          return res.status(200).json({ message: "Task deleted successfully" });
        } else {
          return res.status(404).json({ error: "Task not found" });
        }
      } else {
        // Delete all tasks for the user
        const result = await taskRepository.delete({ username });

        if (result.affected && result.affected > 0) {
          return res
            .status(200)
            .json({ message: "All tasks deleted successfully" });
        } else {
          return res
            .status(404)
            .json({ error: "No tasks found for this user" });
        }
      }
    } catch (error) {
      console.error("Error deleting task(s):", error);
      return res.status(500).json({ error: "Failed to delete tasks" });
    }
  }
);

// Update task
router.put(
  "/updateTask",
  authenticateToken,
  async (req: Request, res: Response) => {
    const { task_id, task_description, task_priority, datetime, is_completed } =
      req.body;

    if (!task_id) {
      return res.status(400).json({ error: "Task ID is required" });
    }

    try {
      const task = await taskRepository.findOne({ where: { task_id } });

      if (!task) {
        return res.status(404).json({ error: "Task not found" });
      }

      if (task_description !== undefined)
        task.task_description = task_description;
      if (task_priority !== undefined) task.task_priority = task_priority;
      if (datetime !== undefined) task.datetime = datetime;
      if (is_completed !== undefined) task.is_completed = is_completed;

      await taskRepository.save(task);

      return res
        .status(200)
        .json({ message: "Task updated successfully", task });
    } catch (error) {
      console.error("Error updating task:", error);
      return res.status(500).json({ error: "Failed to update task" });
    }
  }
);

// ******************* Using raw SQL queries with pool *************************************

// const generateUsername = async (firstname: string, lastname: string) => {
//   // Extract first 4 letters from firstname and lastname
//   const baseUsername =
//     firstname.slice(0, 4).toLowerCase() + lastname.slice(0, 4).toLowerCase();
//   let username = baseUsername;
//   let count = 1;

//   // Check if username already exists in database
//   while (true) {
//     const result = await pool.query("SELECT 1 FROM users WHERE username = $1", [
//       username,
//     ]);
//     if (result.rowCount === 0) break; // Username is unique, exit loop

//     // If exists, append a number and check again
//     username = `${baseUsername}${count}`;
//     count++;
//   }

//   return username;
// };

// const fetchRefreshTokenFromDB = async (
//   req: any,
//   res: any,
//   next: any,
//   expiredAccessToken: string
// ) => {
//   console.error("expiredAccessToken:", expiredAccessToken);

//   try {
//     const decoded: any = jwt.decode(expiredAccessToken);
//     const username = decoded.username;

//     const result = await pool.query(
//       `SELECT "refreshToken" FROM users WHERE username = $1`,
//       [username]
//     );

//     if (result.rows.length === 0) {
//       return res.status(403).json({ error: "Invalid refresh token" });
//     }

//     const refreshToken = result.rows[0].refreshToken;

//     const verifyRefreshToken: any = jwt.verify(
//       refreshToken,
//       process.env.REFRESH_SECRET as string
//     );

//     const newAccessToken = generateAccessToken(verifyRefreshToken.username);

//     res.setHeader("x-new-access-token", newAccessToken);
//     req.body.username = verifyRefreshToken.username;
//     next();
//   } catch (error) {
//     console.error("Refresh Token Error:", error);
//     return res.status(403).json({ error: "Invalid or expired refresh token" });
//   }
// };

// router.post("/register", async (req: any, res: any) => {
//   try {
//     const { firstname, lastname, email, password } = req.body;
//     if (!email || !password) {
//       return res
//         .status(400)
//         .json({ error: "Email & password fields are required" });
//     }

//     // Check if email already exists
//     const existingUser = await pool.query(
//       "SELECT * FROM users WHERE email = $1",
//       [email]
//     );

//     if (existingUser.rows.length > 0) {
//       return res.status(400).json({ error: "Email already registered" });
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);
//     const username = await generateUsername(firstname, lastname);
//     const refreshToken = generateRefreshToken(username);

//     const result = await pool.query(
//       `INSERT INTO users (firstname, lastname, email, password, username, "refreshToken") VALUES ($1, $2, $3, $4, $5, $6)`,
//       [firstname, lastname, email, hashedPassword, username, refreshToken]
//     );

//     return res.status(201).json({
//       message: "User registered successfully",
//     });
//   } catch (error) {
//     console.error("Registration Error:", error);
//     return res.status(500).json({ error: "Error registering user" });
//   }
// });

// router.post("/login", async (req: any, res: any) => {
//   try {
//     const { email, password } = req.body;
//     const userQuery = await pool.query("SELECT * FROM users WHERE email = $1", [
//       email,
//     ]);

//     if (userQuery.rows.length === 0) {
//       return res.status(400).json({ error: "Invalid email id. Try again!!!" });
//     }

//     const user = userQuery.rows[0];

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(400).json({ error: "Wrong password. Try again!!!" });
//     }

//     // Step 1: Check if the existing refresh token is valid
//     if (user.refreshToken) {
//       try {
//         jwt.verify(user.refreshToken, process.env.REFRESH_SECRET as string);
//       } catch (err) {
//         user.refreshToken = generateRefreshToken(user.username);

//         // Step 2: Store the new refresh token in the database
//         await pool.query(
//           `UPDATE users SET "refreshToken" = $1 WHERE email = $2`,
//           [user.refreshToken, email]
//         );
//       }
//     } else {
//       // Step 3: If no refresh token exists, generate one
//       user.refreshToken = generateRefreshToken(user.username);
//       await pool.query(
//         `UPDATE users SET "refreshToken" = $1 WHERE email = $2`,
//         [user.refreshToken, email]
//       );
//     }

//     // Step 4: Generate a new access token
//     const accessToken = generateAccessToken(user.username);

//     return res.json({
//       message: "Login successfull.",
//       accessToken: accessToken,
//       userData: user,
//     });
//   } catch (error) {
//     console.error("Login Error:", error);
//     return res.status(500).json({ error: "Error logging in" });
//   }
// });

// router.post("/refresh", async (req: any, res: any) => {
//   try {
//     const { refreshToken } = req.body;

//     if (!refreshToken) {
//       return res.status(401).json({ error: "Refresh token required" });
//     }

//     // Find user with this refresh token
//     const user = await pool.query(
//       "SELECT * FROM users WHERE refresh_token = $1",
//       [refreshToken]
//     );

//     if (user.rows.length === 0) {
//       return res.status(403).json({ error: "Invalid refresh token" });
//     }

//     // Verify refresh token
//     jwt.verify(
//       refreshToken,
//       process.env.REFRESH_SECRET as string,
//       (err: any, decoded: any) => {
//         if (err)
//           return res.status(403).json({ error: "Invalid refresh token" });

//         // Generate new access token
//         const accessToken = generateAccessToken(decoded.userId);

//         return res.json({
//           message: "New access token generated.",
//           tokens: {
//             accessToken: accessToken,
//           },
//         });
//       }
//     );
//   } catch (error) {
//     console.error("Refresh Token Error:", error);
//     return res.status(500).json({ error: "Error refreshing token" });
//   }
// });

// router.post("/addTask", authenticateToken, async (req: any, res: any) => {
//   try {
//     const task = req.body;

//     const task_id = task.task_id;
//     const username = task.username;
//     const task_priority = task.task_priority;
//     const datetime = task.datetime;
//     const task_description = task.task_description;
//     const is_completed = task.is_completed;

//     const accessUsername = req.body.username;

//     if (accessUsername !== username)
//       return res.status(403).json({ error: "Username is different." });

//     await pool.query(
//       `INSERT INTO tasks (task_id, username, task_priority, datetime, task_description, is_completed)
//        VALUES ($1, $2, $3, $4, $5, $6)`,
//       [
//         task_id,
//         username,
//         task_priority,
//         datetime,
//         task_description,
//         is_completed,
//       ]
//     );

//     return res.json({
//       message: "Task added successfully.",
//     });
//   } catch (error) {
//     console.error("Error:", error);
//     return res.status(500).json({ error: "Task adding failed." });
//   }
// });

// router.get("/getTasks", authenticateToken, async (req: any, res: any) => {
//   const { username } = req.query;
//   if (!username) {
//     return res.status(400).json({ error: "Username is required" });
//   }

//   try {
//     const tasks = await pool.query("SELECT * FROM tasks WHERE username = $1", [
//       username,
//     ]);

//     return res.json({ message: "Task fetching successfull.", tasks: tasks });
//   } catch (error) {
//     res.status(500).json({ error: "Failed to fetch tasks" });
//   }
// });

// router.delete("/deleteTask", authenticateToken, async (req: any, res: any) => {
//   const { username, task_id } = req.query;

//   if (!username) {
//     return res.status(400).json({ error: "Username is required" });
//   }

//   try {
//     if (task_id) {
//       // If task_id is provided, delete the specific task
//       const result = await pool.query(
//         "DELETE FROM tasks WHERE username = $1 AND task_id = $2 RETURNING *",
//         [username, task_id]
//       );

//       if (result.rowCount !== null && result.rowCount > 0) {
//         return res.status(200).json({ message: "Task deleted successfully" });
//       } else {
//         return res.status(404).json({ error: "Task not found" });
//       }
//     } else {
//       // If no task_id is provided, delete all tasks for the user
//       const result = await pool.query(
//         "DELETE FROM tasks WHERE username = $1 RETURNING *",
//         [username]
//       );

//       if (result.rowCount !== null && result.rowCount > 0) {
//         return res
//           .status(200)
//           .json({ message: "All tasks deleted successfully" });
//       } else {
//         return res.status(404).json({ error: "No tasks found for this user" });
//       }
//     }
//   } catch (error) {
//     console.error("Error deleting task or all tasks:", error);
//     return res.status(500).json({ error: "Failed to delete tasks" });
//   }
// });

// router.put("/updateTask", authenticateToken, async (req: any, res: any) => {
//   const { task_id, task_description, task_priority, datetime, is_completed } =
//     req.body;

//   if (!task_id) {
//     return res.status(400).json({ error: "Task ID is required" });
//   }

//   // Prepare dynamic query
//   const fieldsToUpdate = [];
//   const values = [];

//   if (task_description !== undefined) {
//     fieldsToUpdate.push(`task_description = $${values.length + 1}`);
//     values.push(task_description);
//   }
//   if (task_priority !== undefined) {
//     fieldsToUpdate.push(`task_priority = $${values.length + 1}`);
//     values.push(task_priority);
//   }
//   if (datetime !== undefined) {
//     fieldsToUpdate.push(`datetime = $${values.length + 1}`);
//     values.push(datetime);
//   }
//   if (is_completed !== undefined) {
//     fieldsToUpdate.push(`is_completed = $${values.length + 1}`);
//     values.push(is_completed);
//   }

//   if (fieldsToUpdate.length === 0) {
//     return res
//       .status(400)
//       .json({ error: "No valid fields provided for update" });
//   }

//   values.push(task_id);

//   const query = `
//     UPDATE tasks
//     SET ${fieldsToUpdate.join(", ")}
//     WHERE task_id = $${values.length}
//     RETURNING *;
//   `;

//   try {
//     const result = await pool.query(query, values);

//     if (result.rowCount !== null && result.rowCount > 0) {
//       return res
//         .status(200)
//         .json({ message: "Task updated successfully", task: result.rows[0] });
//     } else {
//       return res.status(404).json({ error: "Task not found" });
//     }
//   } catch (error) {
//     console.error("Error updating task:", error);
//     return res.status(500).json({ error: "Failed to update task" });
//   }
// });

export default router;
