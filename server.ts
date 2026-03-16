import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("client_control.db");
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key-123";

// Initialize Database Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    passwordHash TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    contractedService TEXT,
    notes TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS professionals (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    role TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    clientId TEXT NOT NULL,
    professionalId TEXT NOT NULL,
    serviceName TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT,
    status TEXT DEFAULT 'Pendente',
    notes TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (clientId) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (professionalId) REFERENCES professionals(id) ON DELETE CASCADE
  );
`);

// Add default admin if empty
const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
if (userCount.count === 0) {
  const hash = bcrypt.hashSync("admin", 10);
  db.prepare("INSERT INTO users (id, email, passwordHash) VALUES (?, ?, ?)")
    .run("admin-1", "admin@admin.com", hash);
}

async function startServer() {
  const app = express();
  const PORT = 3001;

  app.use(express.json());

  // --- API Routes ---

  // Auth Routes
  app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as any;
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  });

  app.get("/api/auth/check", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Não autorizado" });
    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      res.json({ user: decoded });
    } catch (e) {
      res.status(401).json({ error: "Token inválido" });
    }
  });

  // Auth Middleware for protected routes
  const requireAuth = (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Não autorizado" });
    const token = authHeader.split(" ")[1];
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch (e) {
      res.status(401).json({ error: "Token inválido" });
    }
  };

  app.put("/api/auth/update", requireAuth, (req: any, res: any) => {
    const { currentPassword, newEmail, newPassword } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id) as any;
    if (!bcrypt.compareSync(currentPassword, user.passwordHash)) {
      return res.status(401).json({ error: "Palavra-passe atual incorreta" });
    }
    const hash = newPassword ? bcrypt.hashSync(newPassword, 10) : user.passwordHash;
    const email = newEmail || user.email;
    try {
      db.prepare("UPDATE users SET email = ?, passwordHash = ? WHERE id = ?").run(email, hash, req.user.id);
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: "Erro ao atualizar dados. O email pode já estar em uso." });
    }
  });

  // Protect all API routes below this line
  app.use("/api/clients", requireAuth);
  app.use("/api/professionals", requireAuth);
  app.use("/api/tasks", requireAuth);

  // Clients
  app.get("/api/clients", (req, res) => {
    const clients = db.prepare("SELECT * FROM clients ORDER BY createdAt DESC").all();
    res.json(clients);
  });

  app.get("/api/clients/:id", (req, res) => {
    const client = db.prepare("SELECT * FROM clients WHERE id = ?").get(req.params.id);
    if (!client) return res.status(404).json({ error: "Client not found" });
    res.json(client);
  });

  app.post("/api/clients", (req, res) => {
    const { name, phone, contractedService, notes } = req.body;
    const id = Math.random().toString(36).substring(2, 11);
    db.prepare("INSERT INTO clients (id, name, phone, contractedService, notes) VALUES (?, ?, ?, ?, ?)")
      .run(id, name, phone, contractedService, notes);
    res.status(201).json({ id, name, phone, contractedService, notes });
  });

  app.put("/api/clients/:id", (req, res) => {
    const { name, phone, contractedService, notes } = req.body;
    db.prepare("UPDATE clients SET name = ?, phone = ?, contractedService = ?, notes = ? WHERE id = ?")
      .run(name, phone, contractedService, notes, req.params.id);
    res.json({ id: req.params.id, name, phone, contractedService, notes });
  });

  app.delete("/api/clients/:id", (req, res) => {
    db.prepare("DELETE FROM clients WHERE id = ?").run(req.params.id);
    res.status(204).end();
  });

  // Professionals
  app.get("/api/professionals", (req, res) => {
    const professionals = db.prepare("SELECT * FROM professionals ORDER BY createdAt DESC").all();
    res.json(professionals);
  });

  app.post("/api/professionals", (req, res) => {
    const { name, phone, role } = req.body;
    const id = Math.random().toString(36).substring(2, 11);
    db.prepare("INSERT INTO professionals (id, name, phone, role) VALUES (?, ?, ?, ?)")
      .run(id, name, phone, role);
    res.status(201).json({ id, name, phone, role });
  });

  app.delete("/api/professionals/:id", (req, res) => {
    db.prepare("DELETE FROM professionals WHERE id = ?").run(req.params.id);
    res.status(204).end();
  });

  // Tasks
  app.get("/api/tasks", (req, res) => {
    const { date, clientId } = req.query;
    let query = `
      SELECT tasks.*, clients.name as clientName, professionals.name as professionalName 
      FROM tasks 
      JOIN clients ON tasks.clientId = clients.id 
      JOIN professionals ON tasks.professionalId = professionals.id
    `;
    const params = [];

    if (date || clientId) {
      query += " WHERE 1=1";
      if (date) {
        query += " AND tasks.date = ?";
        params.push(date);
      }
      if (clientId) {
        query += " AND tasks.clientId = ?";
        params.push(clientId);
      }
    }

    query += " ORDER BY tasks.date ASC, tasks.time ASC";
    const tasks = db.prepare(query).all(...params);
    res.json(tasks);
  });

  app.post("/api/tasks", (req, res) => {
    const { clientId, professionalId, serviceName, date, time, notes } = req.body;
    const id = Math.random().toString(36).substring(2, 11);
    db.prepare("INSERT INTO tasks (id, clientId, professionalId, serviceName, date, time, notes) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id, clientId, professionalId, serviceName, date, time, notes);
    res.status(201).json({ id, clientId, professionalId, serviceName, date, time, notes, status: 'Pendente' });
  });

  app.patch("/api/tasks/:id", (req, res) => {
    const { status } = req.body;
    db.prepare("UPDATE tasks SET status = ? WHERE id = ?").run(status, req.params.id);
    res.json({ id: req.params.id, status });
  });

  app.delete("/api/tasks/:id", (req, res) => {
    db.prepare("DELETE FROM tasks WHERE id = ?").run(req.params.id);
    res.status(204).end();
  });

  // --- Vite Middleware ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: { port: 24679 } },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
