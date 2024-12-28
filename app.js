import express from "express";
import jwt from "jsonwebtoken";
import { users } from "./users.js";

const app = express();
app.use(express.json()); // Для обработки JSON-запросов

const SECRET_KEY = "your_jwt_secret";

// Middleware для проверки JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user; // Добавляем данные из токена в запрос
    next();
  });
};

// Маршрут для логина (генерация токена)
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (user) {
    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY,
      {
        expiresIn: "1h",
      }
    );
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

// Защищенный маршрут для обновления email
app.put("/update-email", authenticateJWT, (req, res) => {
  const { email } = req.body;
  const { id } = req.user;

  const user = users.find((u) => u.id === id);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  if (!email || !email.includes("@")) {
    return res.status(400).json({ message: "Invalid email" });
  }

  user.email = email; // Обновляем email пользователя
  res.json({ message: "Email updated successfully", user });
});

// Запуск сервера
app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
