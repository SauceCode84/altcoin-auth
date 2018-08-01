import express from "express";
import bodyParser from "body-parser";
import logger from "morgan";
import uuid from "uuid/v4";

import * as jwt from "jsonwebtoken";

import config from "./config.json";

import { Client } from "pg";
import { randomBytes, createHmac } from "crypto";

const app = express();

const router = express.Router();

export const client = new Client({
  user: "postgres",
  database: "altcoin"
});

client.connect((err) => {
  if (err) {
    console.error("Client Connect ERROR", err);
    return;
  }

  console.log("Client Connected!");
});

router.get("/", (req, res) => {
  res.send("Ok...");
});

interface RegisterDTO {
  username: string;
  password: string;
}

interface User {
  id: string;
  username: string;
  password: string;
  salt: string;
  trading_fees: number;
}

const DEFAULT_TRADING_FEES = 0.8;

const registerUser = async (username: string, password: string) => {
  const sql = "INSERT INTO users (username, password, salt, trading_fees) VALUES ($1, $2, $3, $4) RETURNING id";
  let { passwordHash, salt } = saltHashPassword(password);
  
  let result = await client.query(sql, [username, passwordHash, salt, DEFAULT_TRADING_FEES]);
  
  return result.rows[0].id as string;
}

const getRandomString = (length: number): string => {
  return randomBytes(Math.ceil(length / 2))
    .toString("hex")
    .slice(0, length);
}

const hashPassword = (password: string, salt: string) => {
  let hash = createHmac("sha512", salt);
  hash.update(password);
  
  let passwordHash = hash.digest("hex");

  return { salt, passwordHash };
}

const saltHashPassword = (password: string) => {
  let salt = getRandomString(20);
  return hashPassword(password, salt);
}

const matchPassword = (currentPassword: string, currentSalt: string, password: string) => {
  let { passwordHash } = hashPassword(password, currentSalt);
  return currentPassword === passwordHash;
}

const getUser = async (username: string) => {
  const sql = "SELECT * FROM users WHERE username = $1";
  let result = await client.query(sql, [username]);
  
  return result.rows[0] as User;
}

const authenticateUser = async (username: string, password: string) => {
  let user = await getUser(username);
  let result = matchPassword(user.password, user.salt, password);

  return result ? user : null;
}

router.post("/register", async (req, res) => {
  try {
    let { username, password } = req.body as RegisterDTO;
    let id = await registerUser(username, password);

    res.json({ id });
  } catch (err) {
    res.status(500).send(err);
  }
});

router.post("/login", async (req, res) => {
  let { username, password } = req.body;
  
  // check DB...
  const user = await authenticateUser(username, password);

  if (!user) {
    return res.status(401).end();
  }

  let userLogin = {
    ip: req.header("x-forwarded-for") || req.connection.remoteAddress,
    via: req.header("via") || "none",
    referrer: req.header("referrer"),
    agent: req.header("user-agent")
  };

  console.log("user login", userLogin);
  
  const jti = uuid();
  const client_id = uuid();

  const payload = {
    user_id: user.id,
    client_id
  };

  const token = jwt.sign(payload, config.secret, {
    algorithm: "HS512",
    jwtid: jti,
    expiresIn: config.tokenLife
  });
  
  const refreshToken = jwt.sign({ id: jti }, config.refreshTokenSecret, {
    algorithm: "HS512",
    expiresIn: config.refreshTokenLife
  });

  const response = { token, refreshToken };

  return res.status(200).json(response);
});

app.use(bodyParser.json());
app.use(logger("dev"));

app.use("/api", router);

app.listen(config.port || process.env.PORT || 3000);
