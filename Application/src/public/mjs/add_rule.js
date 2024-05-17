import axios from "axios";
import { showAlert } from "./alerts.js";

export const addrule = async (src_ip, dst_ip, protocol, src_port, dst_port, state, action) => {
  try {
    const res = await axios({
      method: "POST",
      url: "/rule-control",
      data: {
        src_ip, dst_ip, protocol, src_port, dst_port, state, action
      },
    });

    if (res.data.status === "success") {
      showAlert("success", "successfully!");
      window.setTimeout(() => {
        location.assign("/");
      }, 1500);
    }
  } catch (err) {
    console.log(err.response.data.data);
    showAlert("error", err.response.data.error);
  }
};
