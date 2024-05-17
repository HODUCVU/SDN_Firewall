const app = require("./app.js");
const dotenv = require("dotenv");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");
//config dotenv
dotenv.config();
const port = process.env.PORT || 8888;
const httpServer = http.createServer(
  app
);



httpServer.listen(port, () => {
  console.log(`http://localhost:${port}/`);
});
