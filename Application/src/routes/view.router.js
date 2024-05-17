const express = require("express");
const Router = express.Router();
const controller = require("../controller/view.controller")

Router.get("/", controller.home);
Router.get("/rules", controller.rules);

//user
Router.get("/switch", controller.switch);

Router.get("/flow/:id", controller.flow);
Router.post("/rule-control", controller.addRule);
Router.get("/rule-control", async (req, res) => {
  res.status(200).render("rule-form");
});
Router.post("/drop-control", controller.addRule);
Router.get("/drop-control", async (req, res) => {
  res.status(200).render("drop-form");
});



module.exports = Router;
