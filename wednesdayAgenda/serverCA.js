import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

// Simpel "databas" för demo
const users = [
  { id: 1, 
    username: "Posh", 
    password: "1234", 
    role: "admin" 
  },
  { id: 2, 
    username: "Sporty", 
    password: "1234", 
    role: "user" 
  },
  { id: 3, 
    username: "Ginger", 
    password: "1234", 
    role: "admin" 
  },
  { id: 4, 
    username: "Baby", 
    password: "1234", 
    role: "user" 
  },
  { id: 5, 
    username: "Scary", 
    password: "1234", 
    role: "user" 
  }
];

/* LOGIN ROUTE */
// När en användare försöker logga in (POST request)
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({error: "Username and password are required."})
  }

  // Kontrollera användarens inloggningsuppgifter
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user)
    return res.status(401).json({ error: "wrong username or password!" });

  // Skapa JWT-token med användarens id och roll som payload
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" } 
  );

  // Skicka JWT tillbaka till klienten
  res.json({ token });
});

// Generate token (manual JWT creation)
app.post("/generate-token", (req, res) => {
  const {username, role} = req.body;

  if (!username || !role) {
    return res.status(400).json({error: "Username and role are required."});
  }

  // create a JWT token with the provided username and role
  const token = jwt.sign(
    {username, role},
    process.env.JWT_SECRET,
    {expiresIn: "1h"}
  );

  res.json({token});
});

// public route
app.get("/public", (req, res) => {
  res.json({message: "Welcome to the public route!!"})
});

// Protected route, requires a valid JWT token in the header (without middleware)
app.get("/secret", (req, res) => {
  // Check that the JWT token is sent in the Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    // Send an error message if the JWT is completely missing (401 Unauthorized)
    return res.status(401).json({ error: "JWT-token saknas." });
  }

  // The token is "Bearer [token]", we extract the actual token

  //What does it do? When JWT is used in HTTP headers
  // it is typically sent according to the standard: Authorization: Bearer <JWT token>
  const token = authHeader.split(" ")[1];

  // It takes the entire header value, e.g.: "Bearer eyJhbGciOiJIUzI1Ni..."
  // It splits the string at the space (" ") which gives an array with two parts: 
  // ["Bearer", "eyJhbGciOiJIUzI1Ni..."] Then it retrieves the second part [1], i.e., the actual token: "eyJhbGciOiJIUzI1Ni..."

  try {
    // Calls jwt.verify which checks:
    // 1. That the JWT token is valid and correctly signed.
    // 2. That the JWT token has not expired.
    // If verification succeeds, we get back the "payload", i.e., the contents of the JWT.
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    res.json({
      message: "Du är inloggad!",
      user: payload, // Contains data such as userId, username, role, etc.
    });
  } catch (err) {
    // If the token is invalid, tampered with, or has expired, the error is caught here.
    // Then we respond with status code 403 (Forbidden) and a clear error message.
    res.status(403).json({ error: "JWT-token is invalid." });
  }
});

app.listen(8080, () => console.log("✅ Server körs på http://localhost:8080"));
