import axios from "axios";
import { showAlert } from "./alerts.js";

export const changePass = async (password, newPassword) => {
  try {
    const res = await axios({
      method: "PATCH",
      url: "/api/v1/users/updatePassword",
      data: {
        password,
        newPassword,
      },
    });

    if (res.data.status === "success") {
      showAlert("success", "Signup in successfully!");
      window.setTimeout(() => {
        location.assign(`./`);
      }, 1500);
    }
  } catch (err) {
    showAlert("error", err.response.data.error);
  }
};
