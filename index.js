import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const users = [];

const SECRET_KEY = "your_secret_key"; // Секрет для JWT

const app = express();
app.use(express.json()); // Для обработки JSON-запросов

// Маршрут для регистрации
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Проверяем, есть ли пользователь с таким именем
  if (users.find((u) => u.username === username)) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Хэшируем пароль
  const hashedPassword = await bcrypt.hash(password, 10);

  // Сохраняем пользователя
  const newUser = {
    id: users.length + 1,
    username,
    email: "", // email добавится позже
    password: hashedPassword,
  };
  users.push(newUser);
  res.json({ message: "User registered successfully", user: newUser });
});

// Маршрут для логина
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // Проверка пароля
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Генерация JWT
  const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, {
    expiresIn: "1h",
  });
  res.json({ token });
});

// Middleware для проверки токена
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: "Invalid token" });
  }
};

// Маршрут для обновления email
app.put("/update-email", authenticateJWT, (req, res) => {
  const { email } = req.body;
  const userId = req.user.id;

  const user = users.find((u) => u.id === userId);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  user.email = email;
  res.json({ message: "Email updated successfully", user });
});

// Тестовый маршрут
app.get("/", (req, res) => {
  res.send("Сервер работает! Добро пожаловать!");
});

// Запуск сервера
app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
