require('@babel/register');
const path = require("path");
const express = require("express");
const cors = require("cors");
const viewRouter = require("./routes/view.router.js");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const swaggerUi = require("swagger-ui-express");
const fs = require("fs");
const error = require("./uitl/err.js")
const app = express();


app.use(cors());
app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));

// Serving static files
app.use(express.static(path.join(__dirname, "public")));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


app.use("/", viewRouter);
app.all("*", (req, res, next) => {
  next(new error(`Can't find url: ${req.originalUrl} on this server!!!`, 400));
});

module.exports = app;
