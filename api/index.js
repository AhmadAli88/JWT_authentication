import express from "express";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const users = [
  {
    id: "1",
    username: "ahmad",
    password: "ahmad123",
    isAdmin: true,
  },
  {
    id: "2",
    username: "aman",
    password: "aman123",
    isAdmin: false,
  },
];

// Generate Access Token
const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      isAdmin: user.isAdmin,
    },
    "mySecretKey",
    {
      expiresIn: "15m", // Token expires in 15 minutes
    }
  );
};

// Generate Refresh Token
const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      isAdmin: user.isAdmin,
    },
    "myRefreshSecretKey",
    {
      expiresIn: "7d", // Refresh token expires in 7 days
    }
  );
};

let refreshTokens = []; // Store refresh tokens

// Login Route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username && u.password === password);

  if (user) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken); // Store the refresh token

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(401).json({ message: "Invalid username or password" });
  }
});

// Verify Token Middleware
const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated");
  }
};

// Delete User Route
app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted");
  } else {
    res.status(403).json("You are not allowed to delete this user");
  }
});

// Refresh Token Route
app.post("/api/refresh", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(401).json("You are not authenticated");

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Refresh token is not valid");
  }

  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    if (err) {
      return res.status(403).json("Refresh token is not valid");
    }
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    // Replace old refresh token with the new one
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});


app.post("/api/logout", (req, res) => {
    const refreshToken = req.body.token;
    
    // Filter out the token from the refreshTokens array
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    
    res.status(200).json("User has been logged out");
  });
  
// Start the server
app.listen(5000, () => console.log("Backend server is running"));

