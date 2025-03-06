import express from "express";
import cors from "cors";

import taskRoutes from "./routes/taskRoutes";

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(
  cors({
    origin: "*",
    allowedHeaders: [
      "Origin",
      "X-Requested-With",
      "Content-Type",
      "Accept",
      "Authorization",
      "x-new-access-token",
    ],
    exposedHeaders: ["x-new-access-token"],
  })
);
app.use(express.json()); // For parsing JSON data

app.get("/", (req, res) => {
  res.send("Server is running!");
});

app.use("/", taskRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
