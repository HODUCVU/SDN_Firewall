import axios from "axios";
import { showAlert } from "./alerts.js";

export const changePass = async (name, email, gioitinh, sdt, khoa) => {
  try {
    const res = await axios({
      method: "PATCH",
      url: "api/v1/users/me",
      data: {
        name,
        email,
        gioitinh,
        sdt,
        khoa,
      },
    });

    if (res.data.status === "success") {
      showAlert("success", "Signup in successfully!");
      window.setTimeout(() => {
        location.assign(`/`);
      }, 1500);
    }
  } catch (err) {
    showAlert("error", err.response.data.error);
  }
};
