import express from "express";
import bodyParser from "body-parser";
import logger from "morgan";
import uuid from "uuid/v4";

import * as jwt from "jsonwebtoken";

import config from "./config.json";

const app = express();

const router = express.Router();

router.get("/", (req, res) => {
  res.send("Ok...");
});

router.post("/login", (req, res) => {
  let data = req.body;
  let user = {
    email: data.email,
    name: data.name
  };
  
  // check DB...
  
  const jti = uuid();

  const token = jwt.sign(user, config.secret, {
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
