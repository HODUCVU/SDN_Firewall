/* eslint-disable */
import "@babel/polyfill";
import { showAlert } from "./alerts.js";
import { addrule } from "./add_rule.js";



const rulefrom = document.querySelector(".rule-form");
if (rulefrom) {
  rulefrom.addEventListener("submit", (e) => {
    e.preventDefault();     

    const src_ip = document.getElementById("src_ip").value;
    const dst_ip = document.getElementById("dst_ip").value;
    const protocol = document.getElementById("protocol").value;
    const src_port = document.getElementById("src_port").value;
    const dst_port = document.getElementById("dst_port").value;
    const state = document.getElementById("state").value;
    const action = document.getElementById("action").value;

    addrule(src_ip, dst_ip, protocol, src_port, dst_port, state, action);
  });
}

const alertMessage = document.querySelector("body").dataset.alert;
if (alertMessage) showAlert("success", alertMessage, 20);
