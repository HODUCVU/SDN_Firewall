/* eslint-disable */
import axios from "axios";
import { showAlert } from "./alerts.js";

export const forgotPass = async (id) => {
  try {
    const res = await axios({
      method: "POST",
      url: "/forgotPassword",
      data: {
        id,
      },
    });

    if (res.data.status === "success") {
      showAlert("success", res.data.message);
    }
  } catch (err) {
    console.log(err.response.data.data);
    showAlert("error", err.response.data.data.message);
  }
};
